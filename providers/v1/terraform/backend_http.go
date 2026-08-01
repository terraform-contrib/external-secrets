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
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils"
	"github.com/external-secrets/external-secrets/runtime/esutils/resolvers"
	"github.com/external-secrets/external-secrets/runtime/metrics"
)

// httpFetchTimeout bounds a single state fetch even when the reconcile context
// carries no deadline, so a peer that accepts the connection and then stalls
// cannot hold a controller worker indefinitely.
const httpFetchTimeout = 2 * time.Minute

// decorateRequest applies the configured authentication to the outgoing request.
type decorateRequest func(req *http.Request)

func newHTTPFetcher(ctx context.Context, backend *esv1.TerraformHTTPBackend, opts backendOpts) (fetcher, error) {
	httpClient, err := httpClientFor(ctx, backend, opts)
	if err != nil {
		return nil, err
	}

	decorate, err := httpAuthFor(ctx, backend.Auth, opts)
	if err != nil {
		return nil, err
	}

	return httpFetcher(httpClient, backend.URL, decorate), nil
}

func httpFetcher(httpClient *http.Client, address string, decorate decorateRequest) fetcher {
	// State endpoints can carry credentials in the URL itself (userinfo,
	// pre-signed query parameters), so errors must never echo the raw address.
	redacted := redactURL(address)

	return func(ctx context.Context) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, http.NoBody)
		if err != nil {
			return nil, fmt.Errorf("cannot build state request for %s: invalid url", redacted)
		}
		req.Header.Set("Accept", "application/json")
		if decorate != nil {
			decorate(req)
		}

		resp, err := httpClient.Do(req)
		metrics.ObserveAPICall(metricsProvider, metricsCallHTTPGetState, err)
		if err != nil {
			return nil, fmt.Errorf("cannot fetch state from %s: %w", redacted, redactError(err, redacted))
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			// The body may carry the state itself, so it is not safe to echo
			// into an error message. Report the status only.
			return nil, fmt.Errorf("cannot fetch state from %s: unexpected status %s", redacted, resp.Status)
		}
		return readCapped(resp.Body)
	}
}

// redactURL strips userinfo, query, and fragment from a URL so it can be
// reported in errors and events without leaking embedded credentials such as
// pre-signed request signatures.
func redactURL(address string) string {
	parsed, err := url.Parse(address)
	if err != nil {
		return "the configured url"
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	return parsed.String()
}

// redactError keeps transport errors, which routinely embed the request URL,
// from leaking the unredacted address.
func redactError(err error, redacted string) error {
	if err == nil {
		return nil
	}
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		return fmt.Errorf("%s %s: %w", urlErr.Op, redacted, urlErr.Err)
	}
	return err
}

func httpClientFor(ctx context.Context, backend *esv1.TerraformHTTPBackend, opts backendOpts) (*http.Client, error) {
	// On a ClusterSecretStore a caProvider without a namespace is a referent
	// reference: it resolves in the namespace of the referring ExternalSecret.
	// FetchCACertFromSource requires an explicit namespace for cluster stores,
	// so qualify a copy with the reconcile namespace; the referent guard in
	// NewClient guarantees one exists by the time this runs.
	caProvider := backend.CAProvider
	if caProvider != nil && caProvider.Namespace == nil &&
		opts.storeKind == esv1.ClusterSecretStoreKind && opts.namespace != "" {
		qualified := *caProvider
		qualified.Namespace = &opts.namespace
		caProvider = &qualified
	}

	ca, err := esutils.FetchCACertFromSource(ctx, esutils.CreateCertOpts{
		CABundle:   backend.CABundle,
		CAProvider: caProvider,
		StoreKind:  opts.storeKind,
		Namespace:  opts.namespace,
		Client:     opts.kube,
	})
	if err != nil {
		return nil, fmt.Errorf("cannot resolve CA certificate: %w", err)
	}
	if len(ca) == 0 {
		return &http.Client{Timeout: httpFetchTimeout}, nil
	}

	pool, err := x509.SystemCertPool()
	if err != nil {
		pool = x509.NewCertPool()
	}
	if ok := pool.AppendCertsFromPEM(ca); !ok {
		return nil, errors.New("cannot parse the configured CA certificate")
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		RootCAs:    pool,
		MinVersion: tls.VersionTLS12,
	}
	return &http.Client{Transport: transport, Timeout: httpFetchTimeout}, nil
}

func httpAuthFor(ctx context.Context, auth *esv1.TerraformHTTPAuth, opts backendOpts) (decorateRequest, error) {
	if auth == nil {
		return nil, nil
	}

	switch {
	case auth.Basic != nil:
		username, err := resolvers.SecretKeyRef(ctx, opts.kube, opts.storeKind, opts.namespace, &auth.Basic.Username)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve username: %w", err)
		}
		password, err := resolvers.SecretKeyRef(ctx, opts.kube, opts.storeKind, opts.namespace, &auth.Basic.Password)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve password: %w", err)
		}
		return func(req *http.Request) {
			req.SetBasicAuth(username, password)
		}, nil

	case auth.Bearer != nil:
		token, err := resolvers.SecretKeyRef(ctx, opts.kube, opts.storeKind, opts.namespace, &auth.Bearer.Token)
		if err != nil {
			return nil, fmt.Errorf("cannot resolve token: %w", err)
		}
		return func(req *http.Request) {
			req.Header.Set("Authorization", "Bearer "+token)
		}, nil

	default:
		return nil, errors.New("http auth is set but no method is configured")
	}
}

// httpUsesReferentRefs reports whether any secret or CA reference of the http
// backend lacks an explicit namespace.
func httpUsesReferentRefs(backend *esv1.TerraformHTTPBackend) bool {
	if backend.CAProvider != nil && backend.CAProvider.Namespace == nil {
		return true
	}
	if auth := backend.Auth; auth != nil {
		if auth.Basic != nil && (auth.Basic.Username.Namespace == nil || auth.Basic.Password.Namespace == nil) {
			return true
		}
		if auth.Bearer != nil && auth.Bearer.Token.Namespace == nil {
			return true
		}
	}
	return false
}

func validateHTTPBackend(store esv1.GenericStore, backend *esv1.TerraformHTTPBackend) error {
	if backend.URL == "" {
		return errors.New("http backend requires a url")
	}
	parsed, err := url.Parse(backend.URL)
	if err != nil {
		return fmt.Errorf("http backend url is not a valid URL: %w", err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("http backend url must use http or https, got %q", parsed.Scheme)
	}
	if parsed.Host == "" {
		return errors.New("http backend url must have a host")
	}

	// FetchCACertFromSource rejects this at client construction; failing here
	// surfaces the mistake on the store instead of on every ExternalSecret.
	if backend.CAProvider != nil && backend.CAProvider.Namespace != nil &&
		store.GetKind() != esv1.ClusterSecretStoreKind && *backend.CAProvider.Namespace != store.GetNamespace() {
		return errors.New("invalid caProvider: namespace may only differ from the store namespace on a ClusterSecretStore")
	}

	if backend.Auth == nil {
		return nil
	}
	switch {
	case backend.Auth.Basic != nil && backend.Auth.Bearer != nil:
		return errors.New("only one of basic or bearer auth may be configured")
	case backend.Auth.Basic != nil:
		if err := validateSecretKeySelector(store, "usernameSecretRef", backend.Auth.Basic.Username); err != nil {
			return err
		}
		return validateSecretKeySelector(store, "passwordSecretRef", backend.Auth.Basic.Password)
	case backend.Auth.Bearer != nil:
		return validateSecretKeySelector(store, "tokenSecretRef", backend.Auth.Bearer.Token)
	default:
		return errors.New("http auth is set but no method is configured")
	}
}
