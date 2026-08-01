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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

func secretKey(name, key string) esmeta.SecretKeySelector {
	return esmeta.SecretKeySelector{Name: name, Key: key}
}

func secretStore(spec *esv1.TerraformProvider) *esv1.SecretStore {
	return &esv1.SecretStore{
		TypeMeta:   metav1.TypeMeta{Kind: esv1.SecretStoreKind, APIVersion: esv1.SecretStoreKindAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: "tfstate", Namespace: "apps"},
		Spec: esv1.SecretStoreSpec{
			Provider: &esv1.SecretStoreProvider{Terraform: spec},
		},
	}
}

func clusterSecretStore(spec *esv1.TerraformProvider) *esv1.ClusterSecretStore {
	return &esv1.ClusterSecretStore{
		TypeMeta:   metav1.TypeMeta{Kind: esv1.ClusterSecretStoreKind, APIVersion: esv1.ClusterSecretStoreKindAPIVersion},
		ObjectMeta: metav1.ObjectMeta{Name: "tfstate"},
		Spec: esv1.SecretStoreSpec{
			Provider: &esv1.SecretStoreProvider{Terraform: spec},
		},
	}
}

func TestCapabilitiesAreReadOnly(t *testing.T) {
	assert.Equal(t, esv1.SecretStoreReadOnly, NewProvider().Capabilities())
}

func TestProviderSpecSetsExactlyOneField(t *testing.T) {
	spec := ProviderSpec()
	require.NotNil(t, spec.Terraform)
	assert.Equal(t, esv1.MaintenanceStatusMaintained, MaintenanceStatus())
}

func TestValidateStore(t *testing.T) {
	tests := []struct {
		name    string
		store   esv1.GenericStore
		wantErr string
	}{
		{
			name: "valid s3 backend",
			store: secretStore(&esv1.TerraformProvider{
				Backend: esv1.TerraformBackend{
					S3: &esv1.TerraformS3Backend{Bucket: "b", Key: "prod/terraform.tfstate", Region: "eu-west-1"},
				},
			}),
		},
		{
			name: "valid http backend",
			store: secretStore(&esv1.TerraformProvider{
				Backend: esv1.TerraformBackend{
					HTTP: &esv1.TerraformHTTPBackend{URL: "https://example.com/state"},
				},
			}),
		},
		{
			name: "valid kubernetes backend",
			store: secretStore(&esv1.TerraformProvider{
				Backend: esv1.TerraformBackend{
					Kubernetes: &esv1.TerraformKubernetesBackend{SecretSuffix: "platform"},
				},
			}),
		},
		{
			name:    "no backend",
			store:   secretStore(&esv1.TerraformProvider{}),
			wantErr: "found none",
		},
		{
			name: "incomplete s3 backend",
			store: secretStore(&esv1.TerraformProvider{
				Backend: esv1.TerraformBackend{S3: &esv1.TerraformS3Backend{Bucket: "b"}},
			}),
			wantErr: "requires a key",
		},
		{
			name: "store without a terraform provider",
			store: &esv1.SecretStore{
				Spec: esv1.SecretStoreSpec{Provider: &esv1.SecretStoreProvider{}},
			},
			wantErr: "missing terraform provider spec",
		},
	}

	p := NewProvider()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warnings, err := p.ValidateStore(tt.store)
			assert.Nil(t, warnings)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestValidateStoreRejectsNilStore(t *testing.T) {
	_, err := NewProvider().ValidateStore(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "store is nil")
}

// NewClient is exercised through the http backend, which needs no cloud
// credentials, so the wiring from store spec to a working client is covered
// end to end.
func TestNewClientEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(testState))
	}))
	defer srv.Close()

	kube := fake.NewClientBuilder().WithObjects(&corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "tf-creds", Namespace: "apps"},
		Data:       map[string][]byte{"token": []byte("tok")},
	}).Build()

	store := secretStore(&esv1.TerraformProvider{
		SensitiveOnly: true,
		Backend: esv1.TerraformBackend{
			HTTP: &esv1.TerraformHTTPBackend{
				URL: srv.URL,
				Auth: &esv1.TerraformHTTPAuth{
					Bearer: &esv1.TerraformHTTPBearerAuth{Token: secretKey("tf-creds", "token")},
				},
			},
		},
	})

	client, err := NewProvider().NewClient(t.Context(), store, kube, "apps")
	require.NoError(t, err)

	got, err := client.GetSecret(t.Context(), esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	require.NoError(t, err)
	assert.Equal(t, "s3cr3t", string(got))

	// sensitiveOnly from the store spec must reach the client.
	_, err = client.GetSecret(t.Context(), esv1.ExternalSecretDataRemoteRef{Key: "db_endpoint"})
	require.ErrorIs(t, err, esv1.NoSecretErr)

	require.NoError(t, client.Close(t.Context()))
}

func TestNewClientRejectsAMissingSpec(t *testing.T) {
	_, err := NewProvider().NewClient(t.Context(), &esv1.SecretStore{
		Spec: esv1.SecretStoreSpec{Provider: &esv1.SecretStoreProvider{}},
	}, nil, "apps")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing terraform provider spec")
}

func TestNewClientPropagatesCredentialErrors(t *testing.T) {
	kube := fake.NewClientBuilder().Build()

	store := secretStore(&esv1.TerraformProvider{
		Backend: esv1.TerraformBackend{
			HTTP: &esv1.TerraformHTTPBackend{
				URL: "https://example.com/state",
				Auth: &esv1.TerraformHTTPAuth{
					Bearer: &esv1.TerraformHTTPBearerAuth{Token: secretKey("absent", "token")},
				},
			},
		},
	})

	_, err := NewProvider().NewClient(t.Context(), store, kube, "apps")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot resolve token")
}

// A ClusterSecretStore that references objects without an explicit namespace
// (referent authentication) is reconciled by the store controller with an
// empty namespace. NewClient must not try to resolve anything there, and
// Validate must report Unknown so the store does not stay Ready=False forever.
func TestNewClientReferentAuth(t *testing.T) {
	kube := fake.NewClientBuilder().Build()

	tests := []struct {
		name string
		spec *esv1.TerraformProvider
	}{
		{
			name: "http bearer without namespace",
			spec: &esv1.TerraformProvider{
				Backend: esv1.TerraformBackend{
					HTTP: &esv1.TerraformHTTPBackend{
						URL: "https://example.com/state",
						Auth: &esv1.TerraformHTTPAuth{
							Bearer: &esv1.TerraformHTTPBearerAuth{Token: secretKey("tf-creds", "token")},
						},
					},
				},
			},
		},
		{
			name: "kubernetes backend without namespace",
			spec: &esv1.TerraformProvider{
				Backend: esv1.TerraformBackend{
					Kubernetes: &esv1.TerraformKubernetesBackend{SecretSuffix: "platform"},
				},
			},
		},
		{
			name: "s3 secretRef without namespace",
			spec: &esv1.TerraformProvider{
				Backend: esv1.TerraformBackend{
					S3: &esv1.TerraformS3Backend{
						Bucket: "b", Key: "k", Region: "eu-west-1",
						Auth: esv1.AWSAuth{
							SecretRef: &esv1.AWSAuthSecretRef{
								AccessKeyID:     secretKey("aws-creds", "akid"),
								SecretAccessKey: secretKey("aws-creds", "sak"),
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The store controller passes an empty namespace for cluster-scoped stores.
			client, err := NewProvider().NewClient(t.Context(), clusterSecretStore(tt.spec), kube, "")
			require.NoError(t, err, "NewClient must not resolve referent references during store validation")

			result, err := client.(*Client).Validate()
			require.NoError(t, err)
			assert.Equal(t, esv1.ValidationResultUnknown, result)

			// Reads must fail loudly rather than fetch from the wrong namespace.
			_, err = client.GetSecret(t.Context(), esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
			require.ErrorContains(t, err, "referent references")
		})
	}
}

// The referent guard must not swallow explicit namespaces: a ClusterSecretStore
// whose references all carry a namespace is fully resolvable during store
// validation and keeps the eager behavior.
func TestNewClientClusterStoreWithExplicitNamespaces(t *testing.T) {
	ns := "creds"
	kube := fake.NewClientBuilder().Build()

	spec := &esv1.TerraformProvider{
		Backend: esv1.TerraformBackend{
			HTTP: &esv1.TerraformHTTPBackend{
				URL: "https://example.com/state",
				Auth: &esv1.TerraformHTTPAuth{
					Bearer: &esv1.TerraformHTTPBearerAuth{
						Token: esmeta.SecretKeySelector{Name: "absent", Key: "token", Namespace: &ns},
					},
				},
			},
		},
	}

	// The referenced secret does not exist, so eager resolution must surface
	// the failure instead of deferring it.
	_, err := NewProvider().NewClient(t.Context(), clusterSecretStore(spec), kube, "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cannot resolve token")
}
