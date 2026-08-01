/*
Copyright © The ESO Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package terraform

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// tfNamespace is the namespace the state Secret lives in for the tests that
// exercise cross-namespace access from a ClusterSecretStore.
const tfNamespace = "terraform"

// --- s3 ---------------------------------------------------------------------

type fakeS3 struct {
	body   string
	err    error
	gotIn  *s3.GetObjectInput
	closed bool
}

func (f *fakeS3) GetObject(_ context.Context, in *s3.GetObjectInput, _ ...func(*s3.Options)) (*s3.GetObjectOutput, error) {
	f.gotIn = in
	if f.err != nil {
		return nil, f.err
	}
	return &s3.GetObjectOutput{Body: &trackingReader{Reader: strings.NewReader(f.body), closed: &f.closed}}, nil
}

type trackingReader struct {
	io.Reader
	closed *bool
}

func (t *trackingReader) Close() error {
	*t.closed = true
	return nil
}

func TestS3Fetcher(t *testing.T) {
	t.Run("reads the object and closes the body", func(t *testing.T) {
		api := &fakeS3{body: testState}

		got, err := s3Fetcher(api, "tfstate-bucket", "prod/terraform.tfstate")(t.Context())
		require.NoError(t, err)
		assert.Equal(t, testState, string(got))
		assert.Equal(t, "tfstate-bucket", *api.gotIn.Bucket)
		assert.Equal(t, "prod/terraform.tfstate", *api.gotIn.Key)
		assert.True(t, api.closed, "the response body must be closed")
	})

	t.Run("a missing object is reported clearly", func(t *testing.T) {
		api := &fakeS3{err: &s3types.NoSuchKey{}}

		_, err := s3Fetcher(api, "tfstate-bucket", "prod/terraform.tfstate")(t.Context())
		require.Error(t, err)
		assert.Contains(t, err.Error(), `state object "prod/terraform.tfstate" not found in bucket "tfstate-bucket"`)
	})

	t.Run("other errors are wrapped", func(t *testing.T) {
		sentinel := errors.New("access denied")
		api := &fakeS3{err: sentinel}

		_, err := s3Fetcher(api, "b", "k")(t.Context())
		require.ErrorIs(t, err, sentinel)
	})

	t.Run("an oversized object is rejected", func(t *testing.T) {
		api := &fakeS3{body: strings.Repeat("a", maxStateSize+1)}

		_, err := s3Fetcher(api, "b", "k")(t.Context())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds the")
	})
}

func TestValidateS3Backend(t *testing.T) {
	store := secretStore(&esv1.TerraformProvider{})
	base := func() *esv1.TerraformS3Backend {
		return &esv1.TerraformS3Backend{Bucket: "b", Key: "k", Region: "eu-west-1"}
	}

	require.NoError(t, validateS3Backend(store, base()))

	missingBucket := base()
	missingBucket.Bucket = ""
	assert.ErrorContains(t, validateS3Backend(store, missingBucket), "requires a bucket")

	missingKey := base()
	missingKey.Key = ""
	assert.ErrorContains(t, validateS3Backend(store, missingKey), "requires a key")

	missingRegion := base()
	missingRegion.Region = ""
	assert.ErrorContains(t, validateS3Backend(store, missingRegion), "requires a region")

	emptyJWT := base()
	emptyJWT.Auth.JWTAuth = &esv1.AWSJWTAuth{}
	assert.ErrorContains(t, validateS3Backend(store, emptyJWT), "requires a serviceAccountRef")
}

// --- http -------------------------------------------------------------------

func TestHTTPFetcher(t *testing.T) {
	t.Run("fetches the state", func(t *testing.T) {
		var gotAuth, gotAccept string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotAuth = r.Header.Get("Authorization")
			gotAccept = r.Header.Get("Accept")
			_, _ = w.Write([]byte(testState))
		}))
		defer srv.Close()

		got, err := httpFetcher(srv.Client(), srv.URL, func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer tok")
		})(t.Context())

		require.NoError(t, err)
		assert.Equal(t, testState, string(got))
		assert.Equal(t, "Bearer tok", gotAuth)
		assert.Equal(t, "application/json", gotAccept)
	})

	t.Run("works without auth", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write([]byte(testState))
		}))
		defer srv.Close()

		got, err := httpFetcher(srv.Client(), srv.URL, nil)(t.Context())
		require.NoError(t, err)
		assert.Equal(t, testState, string(got))
	})

	t.Run("a non-200 reports the status but never the body", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte("super-secret-leak"))
		}))
		defer srv.Close()

		_, err := httpFetcher(srv.Client(), srv.URL, nil)(t.Context())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "403")
		assert.NotContains(t, err.Error(), "super-secret-leak")
	})

	t.Run("a transport error is wrapped", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
		url := srv.URL
		srv.Close()

		_, err := httpFetcher(http.DefaultClient, url, nil)(t.Context())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot fetch state")
	})
}

func TestHTTPAuthFor(t *testing.T) {
	kube := fake.NewClientBuilder().WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tf-creds", Namespace: "apps"},
		Data: map[string][]byte{
			"username": []byte("gitlab-ci"),
			"password": []byte("pw"),
			"token":    []byte("tok"),
		},
	}).Build()
	opts := backendOpts{kube: kube, storeKind: esv1.SecretStoreKind, namespace: "apps"}

	t.Run("basic", func(t *testing.T) {
		decorate, err := httpAuthFor(t.Context(), &esv1.TerraformHTTPAuth{
			Basic: &esv1.TerraformHTTPBasicAuth{
				Username: secretKey("tf-creds", "username"),
				Password: secretKey("tf-creds", "password"),
			},
		}, opts)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
		decorate(req)
		user, pass, ok := req.BasicAuth()
		require.True(t, ok)
		assert.Equal(t, "gitlab-ci", user)
		assert.Equal(t, "pw", pass)
	})

	t.Run("bearer", func(t *testing.T) {
		decorate, err := httpAuthFor(t.Context(), &esv1.TerraformHTTPAuth{
			Bearer: &esv1.TerraformHTTPBearerAuth{Token: secretKey("tf-creds", "token")},
		}, opts)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "http://example.com", http.NoBody)
		decorate(req)
		assert.Equal(t, "Bearer tok", req.Header.Get("Authorization"))
	})

	t.Run("nil auth means no decoration", func(t *testing.T) {
		decorate, err := httpAuthFor(t.Context(), nil, opts)
		require.NoError(t, err)
		assert.Nil(t, decorate)
	})

	t.Run("a missing secret is reported", func(t *testing.T) {
		_, err := httpAuthFor(t.Context(), &esv1.TerraformHTTPAuth{
			Bearer: &esv1.TerraformHTTPBearerAuth{Token: secretKey("absent", "token")},
		}, opts)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cannot resolve token")
	})
}

func TestValidateHTTPBackend(t *testing.T) {
	store := secretStore(&esv1.TerraformProvider{})

	require.NoError(t, validateHTTPBackend(store, &esv1.TerraformHTTPBackend{URL: "https://gitlab.example.com/api/v4/state"}))

	assert.ErrorContains(t, validateHTTPBackend(store, &esv1.TerraformHTTPBackend{}), "requires a url")
	assert.ErrorContains(t, validateHTTPBackend(store, &esv1.TerraformHTTPBackend{URL: "ftp://example.com"}), "must use http or https")
	assert.ErrorContains(t, validateHTTPBackend(store, &esv1.TerraformHTTPBackend{URL: "https://"}), "must have a host")

	both := &esv1.TerraformHTTPBackend{
		URL: "https://example.com",
		Auth: &esv1.TerraformHTTPAuth{
			Basic:  &esv1.TerraformHTTPBasicAuth{},
			Bearer: &esv1.TerraformHTTPBearerAuth{},
		},
	}
	assert.ErrorContains(t, validateHTTPBackend(store, both), "only one of basic or bearer")

	empty := &esv1.TerraformHTTPBackend{URL: "https://example.com", Auth: &esv1.TerraformHTTPAuth{}}
	assert.ErrorContains(t, validateHTTPBackend(store, empty), "no method is configured")

	// A SecretStore must not reach into another namespace for its CA.
	foreign := "elsewhere"
	own := "apps"
	caIn := func(ns *string) *esv1.TerraformHTTPBackend {
		return &esv1.TerraformHTTPBackend{
			URL:        "https://example.com",
			CAProvider: &esv1.CAProvider{Type: esv1.CAProviderTypeSecret, Name: "ca", Key: "ca.crt", Namespace: ns},
		}
	}
	assert.ErrorContains(t, validateHTTPBackend(store, caIn(&foreign)), "invalid caProvider")
	require.NoError(t, validateHTTPBackend(store, caIn(&own)))
	require.NoError(t, validateHTTPBackend(store, caIn(nil)))
	require.NoError(t, validateHTTPBackend(clusterSecretStore(&esv1.TerraformProvider{}), caIn(&foreign)))
}

// --- kubernetes -------------------------------------------------------------

func TestStateSecretName(t *testing.T) {
	assert.Equal(t, "tfstate-default-platform", stateSecretName("", "platform"))
	assert.Equal(t, "tfstate-default-platform", stateSecretName("default", "platform"))
	assert.Equal(t, "tfstate-staging-platform", stateSecretName("staging", "platform"))
}

func TestKubernetesFetcher(t *testing.T) {
	var gzipped strings.Builder
	zw := gzip.NewWriter(&gzipped)
	_, err := zw.Write([]byte(testState))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	encoded := base64.StdEncoding.EncodeToString([]byte(gzipped.String()))

	kube := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tfstate-default-platform", Namespace: "apps"},
			Data:       map[string][]byte{stateSecretKey: []byte(encoded)},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tfstate-default-platform", Namespace: tfNamespace},
			Data:       map[string][]byte{stateSecretKey: []byte(testState)},
		},
	).Build()

	t.Run("reads and decodes the state from the ExternalSecret namespace", func(t *testing.T) {
		fetch, err := newKubernetesFetcher(
			&esv1.TerraformKubernetesBackend{SecretSuffix: "platform"},
			backendOpts{kube: kube, storeKind: esv1.SecretStoreKind, namespace: "apps"},
		)
		require.NoError(t, err)

		raw, err := fetch(t.Context())
		require.NoError(t, err)
		st, err := parseState(raw)
		require.NoError(t, err)
		assert.Len(t, st.Outputs, 7)
	})

	t.Run("a ClusterSecretStore may name another namespace", func(t *testing.T) {
		ns := tfNamespace
		fetch, err := newKubernetesFetcher(
			&esv1.TerraformKubernetesBackend{SecretSuffix: "platform", Namespace: &ns},
			backendOpts{kube: kube, storeKind: esv1.ClusterSecretStoreKind, namespace: "apps"},
		)
		require.NoError(t, err)

		raw, err := fetch(t.Context())
		require.NoError(t, err)
		assert.Equal(t, testState, string(raw))
	})

	t.Run("a SecretStore cannot escape its namespace", func(t *testing.T) {
		ns := tfNamespace
		fetch, err := newKubernetesFetcher(
			&esv1.TerraformKubernetesBackend{SecretSuffix: "platform", Namespace: &ns},
			backendOpts{kube: kube, storeKind: esv1.SecretStoreKind, namespace: "other"},
		)
		require.NoError(t, err)

		_, err = fetch(t.Context())
		require.Error(t, err)
	})

	t.Run("a missing Secret is reported", func(t *testing.T) {
		fetch, err := newKubernetesFetcher(
			&esv1.TerraformKubernetesBackend{SecretSuffix: "absent"},
			backendOpts{kube: kube, storeKind: esv1.SecretStoreKind, namespace: "apps"},
		)
		require.NoError(t, err)

		_, err = fetch(t.Context())
		require.Error(t, err)
		assert.Contains(t, err.Error(), `cannot read state from Secret "tfstate-default-absent"`)
	})
}

func TestValidateKubernetesBackend(t *testing.T) {
	ns := tfNamespace

	require.NoError(t, validateKubernetesBackend(
		secretStore(&esv1.TerraformProvider{}),
		&esv1.TerraformKubernetesBackend{SecretSuffix: "platform"},
	))

	assert.ErrorContains(t, validateKubernetesBackend(
		secretStore(&esv1.TerraformProvider{}),
		&esv1.TerraformKubernetesBackend{},
	), "requires a secretSuffix")

	// A SecretStore may not point at a foreign namespace.
	assert.Error(t, validateKubernetesBackend(
		secretStore(&esv1.TerraformProvider{}),
		&esv1.TerraformKubernetesBackend{SecretSuffix: "platform", Namespace: &ns},
	))

	require.NoError(t, validateKubernetesBackend(
		clusterSecretStore(&esv1.TerraformProvider{}),
		&esv1.TerraformKubernetesBackend{SecretSuffix: "platform", Namespace: &ns},
	))
}

// --- dispatch ---------------------------------------------------------------

func TestValidateBackendRequiresExactlyOne(t *testing.T) {
	store := secretStore(&esv1.TerraformProvider{})

	assert.ErrorContains(t, validateBackend(store, &esv1.TerraformBackend{}), "found none")

	assert.ErrorContains(t, validateBackend(store, &esv1.TerraformBackend{
		S3:   &esv1.TerraformS3Backend{Bucket: "b", Key: "k", Region: "r"},
		HTTP: &esv1.TerraformHTTPBackend{URL: "https://example.com"},
	}), "found multiple")
}

// The kubernetes backend splits state whose compressed form exceeds 1 MiB into
// additional Secrets suffixed -part-N, each holding the next slice of the same
// gzip stream.
func TestKubernetesFetcherChunkedState(t *testing.T) {
	var gzipped strings.Builder
	zw := gzip.NewWriter(&gzipped)
	_, err := zw.Write([]byte(testState))
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	payload := []byte(gzipped.String())

	// Split mid-stream so that no chunk is independently decodable.
	third := len(payload) / 3
	chunks := [][]byte{payload[:third], payload[third : 2*third], payload[2*third:]}

	kube := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tfstate-default-platform", Namespace: "apps"},
			Data:       map[string][]byte{stateSecretKey: chunks[0]},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tfstate-default-platform-part-1", Namespace: "apps"},
			Data:       map[string][]byte{stateSecretKey: chunks[1]},
		},
		&corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{Name: "tfstate-default-platform-part-2", Namespace: "apps"},
			Data:       map[string][]byte{stateSecretKey: chunks[2]},
		},
	).Build()

	fetch, err := newKubernetesFetcher(
		&esv1.TerraformKubernetesBackend{SecretSuffix: "platform"},
		backendOpts{kube: kube, storeKind: esv1.SecretStoreKind, namespace: "apps"},
	)
	require.NoError(t, err)

	raw, err := fetch(t.Context())
	require.NoError(t, err)
	st, err := parseState(raw)
	require.NoError(t, err)
	assert.Len(t, st.Outputs, 7)
}

func TestHTTPFetcherRedactsURL(t *testing.T) {
	t.Run("status errors omit query and userinfo", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusForbidden)
		}))
		defer srv.Close()

		signed := srv.URL + "/state?X-Amz-Signature=presigned-sekret"
		_, err := httpFetcher(srv.Client(), signed, nil)(t.Context())
		require.Error(t, err)
		assert.Contains(t, err.Error(), srv.URL+"/state")
		assert.NotContains(t, err.Error(), "presigned-sekret")
	})

	t.Run("transport errors omit query and userinfo", func(t *testing.T) {
		_, err := httpFetcher(
			&http.Client{},
			"http://user:hunter2@127.0.0.1:1/state?X-Amz-Signature=presigned-sekret",
			nil,
		)(t.Context())
		require.Error(t, err)
		assert.NotContains(t, err.Error(), "hunter2")
		assert.NotContains(t, err.Error(), "presigned-sekret")
	})
}

// On a ClusterSecretStore an unqualified caProvider is a referent reference: it
// must resolve in the ExternalSecret namespace at reconcile time rather than
// failing for lack of an explicit namespace.
func TestHTTPClientForReferentCA(t *testing.T) {
	kube := fake.NewClientBuilder().WithScheme(scheme()).WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "state-ca", Namespace: "apps"},
		Data:       map[string][]byte{"ca.crt": []byte("not a pem")},
	}).Build()

	backend := &esv1.TerraformHTTPBackend{
		URL: "https://example.com/state",
		CAProvider: &esv1.CAProvider{
			Type: esv1.CAProviderTypeSecret,
			Name: "state-ca",
			Key:  "ca.crt",
		},
	}

	_, err := httpClientFor(t.Context(), backend, backendOpts{
		kube:      kube,
		storeKind: esv1.ClusterSecretStoreKind,
		namespace: "apps",
	})

	// The garbage certificate proves the reference resolved in the
	// ExternalSecret namespace: the failure is the PEM parse, not the
	// "missing namespace on caProvider secret" refusal.
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot parse the configured CA certificate")
	assert.NotContains(t, err.Error(), "missing namespace")
}

func TestNewFetcherWithoutBackend(t *testing.T) {
	_, err := newFetcher(t.Context(), &esv1.TerraformBackend{}, backendOpts{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no state backend configured")
}

func scheme() *runtime.Scheme {
	s := runtime.NewScheme()
	_ = corev1.AddToScheme(s)
	return s
}
