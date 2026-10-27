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
	"errors"
	"fmt"
	"io"

	"sigs.k8s.io/controller-runtime/pkg/client"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	awsutil "github.com/external-secrets/external-secrets/providers/v1/aws/util"
)

// maxStateSize bounds how much we read off a backend before decoding. State
// files are routinely a few MiB; this is generous enough not to bite while
// still capping memory use.
const maxStateSize = 64 << 20 // 64 MiB

// Label values for runtime/metrics.ObserveAPICall.
const (
	metricsProvider         = "Terraform"
	metricsCallS3GetObject  = "S3.GetObject"
	metricsCallHTTPGetState = "HTTP.GetState"
	metricsCallK8sGetSecret = "Kubernetes.GetSecret"
)

// fetcher retrieves the raw state document from a backend. It is created once
// per client so that credential resolution and connection setup happen up
// front, and is then safe to call repeatedly.
type fetcher func(ctx context.Context) ([]byte, error)

// backendOpts carries everything a backend needs to resolve its own credentials.
type backendOpts struct {
	kube      client.Client
	storeKind string
	// namespace of the ExternalSecret being reconciled. Referenced objects
	// resolve here unless a ClusterSecretStore names another namespace.
	namespace string
}

// newFetcher builds the fetcher for the configured backend.
func newFetcher(ctx context.Context, backend *esv1.TerraformBackend, opts backendOpts) (fetcher, error) {
	switch {
	case backend.S3 != nil:
		return newS3Fetcher(ctx, backend.S3, opts)
	case backend.HTTP != nil:
		return newHTTPFetcher(ctx, backend.HTTP, opts)
	case backend.Kubernetes != nil:
		return newKubernetesFetcher(backend.Kubernetes, opts)
	default:
		return nil, errors.New("no state backend configured")
	}
}

// usesReferentRefs reports whether the backend references any object without an
// explicit namespace. On a ClusterSecretStore such references resolve in the
// namespace of the referring ExternalSecret (referent authentication), so they
// cannot be resolved during store validation, where no namespace exists yet.
func usesReferentRefs(backend *esv1.TerraformBackend) bool {
	switch {
	case backend.S3 != nil:
		return awsutil.IsReferentSpec(backend.S3.Auth)
	case backend.HTTP != nil:
		return httpUsesReferentRefs(backend.HTTP)
	case backend.Kubernetes != nil:
		return backend.Kubernetes.Namespace == nil
	default:
		return false
	}
}

// validateBackend reports whether the backend section is well formed. It runs in
// the webhook, so it must not perform any I/O. The store is needed to tell
// whether references may point at another namespace.
func validateBackend(store esv1.GenericStore, backend *esv1.TerraformBackend) error {
	configured := 0
	for _, set := range []bool{backend.S3 != nil, backend.HTTP != nil, backend.Kubernetes != nil} {
		if set {
			configured++
		}
	}
	switch configured {
	case 1:
	case 0:
		return errors.New("exactly one backend must be configured, found none")
	default:
		return errors.New("exactly one backend must be configured, found multiple")
	}

	switch {
	case backend.S3 != nil:
		return validateS3Backend(store, backend.S3)
	case backend.HTTP != nil:
		return validateHTTPBackend(store, backend.HTTP)
	default:
		return validateKubernetesBackend(store, backend.Kubernetes)
	}
}

// readCapped reads at most maxStateSize bytes, erroring instead of silently
// truncating a document that is too large to be a state file we can handle.
func readCapped(r io.Reader) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxStateSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot read state: %w", err)
	}
	if len(body) > maxStateSize {
		return nil, fmt.Errorf("state exceeds the %d byte limit", maxStateSize)
	}
	return body, nil
}
