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

	apierrors "k8s.io/apimachinery/pkg/api/errors"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
	"github.com/external-secrets/external-secrets/runtime/esutils"
	"github.com/external-secrets/external-secrets/runtime/esutils/resolvers"
	"github.com/external-secrets/external-secrets/runtime/metrics"
)

const (
	// defaultWorkspace is the workspace Terraform uses when none is selected.
	defaultWorkspace = "default"
	// stateSecretKey is the Secret key the kubernetes backend writes the state to.
	stateSecretKey = "tfstate"
)

// stateSecretName mirrors the naming the Terraform kubernetes backend uses.
func stateSecretName(workspace, secretSuffix string) string {
	if workspace == "" {
		workspace = defaultWorkspace
	}
	return fmt.Sprintf("tfstate-%s-%s", workspace, secretSuffix)
}

func newKubernetesFetcher(backend *esv1.TerraformKubernetesBackend, opts backendOpts) (fetcher, error) {
	// Resolving through a SecretKeySelector gets the ClusterSecretStore
	// namespace scoping rules for free: a SecretStore can only ever read from
	// the namespace of the ExternalSecret.
	ref := esmeta.SecretKeySelector{
		Name:      stateSecretName(backend.Workspace, backend.SecretSuffix),
		Key:       stateSecretKey,
		Namespace: backend.Namespace,
	}

	return func(ctx context.Context) ([]byte, error) {
		raw, err := resolvers.SecretKeyRef(ctx, opts.kube, opts.storeKind, opts.namespace, &ref)
		metrics.ObserveAPICall(metricsProvider, metricsCallK8sGetSecret, err)
		if err != nil {
			return nil, fmt.Errorf("cannot read state from Secret %q: %w", ref.Name, err)
		}
		data := []byte(raw)

		// The backend splits state whose compressed form exceeds 1 MiB across
		// additional Secrets named `<name>-part-N`, each holding the next slice
		// of the same gzip stream. Read them in order until one is missing.
		for part := 1; ; part++ {
			partRef := ref
			partRef.Name = fmt.Sprintf("%s-part-%d", ref.Name, part)

			chunk, err := resolvers.SecretKeyRef(ctx, opts.kube, opts.storeKind, opts.namespace, &partRef)
			if apierrors.IsNotFound(err) {
				break
			}
			metrics.ObserveAPICall(metricsProvider, metricsCallK8sGetSecret, err)
			if err != nil {
				return nil, fmt.Errorf("cannot read state chunk from Secret %q: %w", partRef.Name, err)
			}
			data = append(data, chunk...)

			if len(data) > maxStateSize {
				return nil, fmt.Errorf("state exceeds the %d byte limit", maxStateSize)
			}
		}

		if len(data) > maxStateSize {
			return nil, fmt.Errorf("state exceeds the %d byte limit", maxStateSize)
		}
		return data, nil
	}, nil
}

func validateKubernetesBackend(store esv1.GenericStore, backend *esv1.TerraformKubernetesBackend) error {
	if backend.SecretSuffix == "" {
		return errors.New("kubernetes backend requires a secretSuffix")
	}
	return validateSecretKeySelector(store, "namespace", esmeta.SecretKeySelector{
		Name:      stateSecretName(backend.Workspace, backend.SecretSuffix),
		Key:       stateSecretKey,
		Namespace: backend.Namespace,
	})
}

// validateSecretKeySelector checks the namespace scoping of a reference and
// reports which field was at fault.
func validateSecretKeySelector(store esv1.GenericStore, field string, ref esmeta.SecretKeySelector) error {
	if err := esutils.ValidateReferentSecretSelector(store, ref); err != nil {
		return fmt.Errorf("invalid %s: %w", field, err)
	}
	return nil
}
