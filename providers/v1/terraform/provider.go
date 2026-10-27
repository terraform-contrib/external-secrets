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

// Package terraform implements a secret store provider that reads root module
// outputs from Terraform / OpenTofu state.
package terraform

import (
	"context"
	"errors"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// Provider constructs clients that read Terraform / OpenTofu state.
type Provider struct{}

var _ esv1.Provider = &Provider{}

// NewClient constructs a client for the state backend configured on the store.
func (p *Provider) NewClient(ctx context.Context, store esv1.GenericStore, kube client.Client, namespace string) (esv1.SecretsClient, error) {
	spec, err := providerSpec(store)
	if err != nil {
		return nil, err
	}

	// Allow SecretStore controller validation to pass when using referent
	// namespaces: the controller reconciles a ClusterSecretStore without a
	// namespace, and a reference without an explicit namespace only resolves
	// inside an ExternalSecret reconcile.
	if namespace == "" && store.GetKind() == esv1.ClusterSecretStoreKind && usesReferentRefs(&spec.Backend) {
		return &Client{
			referent:      true,
			sensitiveOnly: spec.SensitiveOnly,
			fetch: func(context.Context) ([]byte, error) {
				return nil, errors.New("referent references can only be resolved in the context of an ExternalSecret")
			},
		}, nil
	}

	fetch, err := newFetcher(ctx, &spec.Backend, backendOpts{
		kube:      kube,
		storeKind: store.GetKind(),
		namespace: namespace,
	})
	if err != nil {
		return nil, err
	}

	return &Client{
		fetch:         fetch,
		sensitiveOnly: spec.SensitiveOnly,
	}, nil
}

// ValidateStore checks the store configuration without performing any I/O.
func (p *Provider) ValidateStore(store esv1.GenericStore) (admission.Warnings, error) {
	spec, err := providerSpec(store)
	if err != nil {
		return nil, err
	}
	return nil, validateBackend(store, &spec.Backend)
}

// Capabilities reports that this provider only ever reads.
func (p *Provider) Capabilities() esv1.SecretStoreCapabilities {
	return esv1.SecretStoreReadOnly
}

func providerSpec(store esv1.GenericStore) (*esv1.TerraformProvider, error) {
	if store == nil {
		return nil, errors.New("store is nil")
	}
	spec := store.GetSpec()
	if spec == nil || spec.Provider == nil || spec.Provider.Terraform == nil {
		return nil, errors.New("missing terraform provider spec")
	}
	return spec.Provider.Terraform, nil
}

// NewProvider creates a new Provider instance.
func NewProvider() esv1.Provider {
	return &Provider{}
}

// ProviderSpec returns the provider specification for registration.
func ProviderSpec() *esv1.SecretStoreProvider {
	return &esv1.SecretStoreProvider{
		Terraform: &esv1.TerraformProvider{},
	}
}

// MaintenanceStatus returns the maintenance status of the provider.
func MaintenanceStatus() esv1.MaintenanceStatus {
	return esv1.MaintenanceStatusMaintained
}
