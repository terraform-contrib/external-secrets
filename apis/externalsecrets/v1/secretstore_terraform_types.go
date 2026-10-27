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

package v1

import (
	esmeta "github.com/external-secrets/external-secrets/apis/meta/v1"
)

// TerraformProvider configures a store to read secrets from the state file
// written by Terraform or OpenTofu.
//
// The state is treated as a read-only source: the provider only ever fetches
// and parses it, it never writes it back. Values are addressed by root module
// output name; see the provider documentation for the rationale.
type TerraformProvider struct {
	// Backend describes where the state file is stored. Exactly one backend
	// must be configured.
	Backend TerraformBackend `json:"backend"`

	// SensitiveOnly restricts reads to outputs that are marked `sensitive = true`
	// in the Terraform configuration. Requesting a non-sensitive output from a
	// store with this enabled behaves as if the output did not exist.
	// +optional
	SensitiveOnly bool `json:"sensitiveOnly,omitempty"`
}

// TerraformBackend selects the state backend to read from.
// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type TerraformBackend struct {
	// S3 reads the state from an S3 bucket, as written by the `s3` backend.
	// +optional
	S3 *TerraformS3Backend `json:"s3,omitempty"`

	// HTTP reads the state over HTTP(S), as written by the `http` backend.
	// This also covers state served by the many HTTP-backend implementations,
	// such as the GitLab-managed Terraform state.
	// +optional
	HTTP *TerraformHTTPBackend `json:"http,omitempty"`

	// Kubernetes reads the state from a Kubernetes Secret, as written by the
	// `kubernetes` backend.
	// +optional
	Kubernetes *TerraformKubernetesBackend `json:"kubernetes,omitempty"`
}

// TerraformS3Backend points at a state object in an S3 (or S3-compatible) bucket.
type TerraformS3Backend struct {
	// Bucket holding the state object.
	// +kubebuilder:validation:MinLength=1
	Bucket string `json:"bucket"`

	// Key is the full path of the state object inside the bucket, matching the
	// `key` of the Terraform backend. For a non-default workspace this includes
	// the workspace key prefix, e.g. `env:/staging/prod/terraform.tfstate`.
	// +kubebuilder:validation:MinLength=1
	Key string `json:"key"`

	// Region the bucket lives in.
	// +kubebuilder:validation:MinLength=1
	Region string `json:"region"`

	// Endpoint overrides the S3 endpoint. Set this for S3-compatible object
	// stores such as MinIO or Ceph.
	// +optional
	Endpoint string `json:"endpoint,omitempty"`

	// ForcePathStyle addresses buckets as a path element of the endpoint
	// instead of a subdomain. Most S3-compatible stores require this.
	// +optional
	ForcePathStyle bool `json:"forcePathStyle,omitempty"`

	// Auth defines how to authenticate against AWS. If not set, the AWS SDK
	// default credential chain is used, which covers IRSA and EKS Pod Identity.
	// +optional
	Auth AWSAuth `json:"auth,omitempty"`

	// Role is a Role ARN the provider assumes before reading the object.
	// +optional
	Role string `json:"role,omitempty"`
}

// TerraformHTTPBackend points at state served over HTTP(S).
type TerraformHTTPBackend struct {
	// URL the state is fetched from with a GET request. This is the `address`
	// of the Terraform `http` backend. It must be an http or https URL; store
	// validation rejects anything else.
	// +kubebuilder:validation:MinLength=1
	URL string `json:"url"`

	// Auth defines how to authenticate against the endpoint. If not set the
	// request is sent unauthenticated.
	// +optional
	Auth *TerraformHTTPAuth `json:"auth,omitempty"`

	// CABundle is a PEM-encoded CA bundle used to validate the endpoint
	// certificate.
	// +optional
	CABundle []byte `json:"caBundle,omitempty"`

	// CAProvider points at a ConfigMap or Secret holding the CA bundle used to
	// validate the endpoint certificate.
	// +optional
	CAProvider *CAProvider `json:"caProvider,omitempty"`
}

// TerraformHTTPAuth selects how to authenticate against an HTTP state backend.
// +kubebuilder:validation:MinProperties=1
// +kubebuilder:validation:MaxProperties=1
type TerraformHTTPAuth struct {
	// Basic authenticates with HTTP basic auth.
	// +optional
	Basic *TerraformHTTPBasicAuth `json:"basic,omitempty"`

	// Bearer authenticates with an `Authorization: Bearer` header.
	// +optional
	Bearer *TerraformHTTPBearerAuth `json:"bearer,omitempty"`
}

// TerraformHTTPBasicAuth holds the credentials for HTTP basic auth.
type TerraformHTTPBasicAuth struct {
	// Username to authenticate with.
	Username esmeta.SecretKeySelector `json:"usernameSecretRef"`

	// Password to authenticate with.
	Password esmeta.SecretKeySelector `json:"passwordSecretRef"`
}

// TerraformHTTPBearerAuth holds the token for bearer auth.
type TerraformHTTPBearerAuth struct {
	// Token sent in the Authorization header.
	Token esmeta.SecretKeySelector `json:"tokenSecretRef"`
}

// TerraformKubernetesBackend points at state stored in a Kubernetes Secret.
type TerraformKubernetesBackend struct {
	// SecretSuffix as configured on the Terraform backend. The state is read
	// from the Secret named `tfstate-{workspace}-{secretSuffix}`.
	// +kubebuilder:validation:MinLength=1
	SecretSuffix string `json:"secretSuffix"`

	// Workspace the state belongs to.
	// +kubebuilder:default=default
	// +optional
	Workspace string `json:"workspace,omitempty"`

	// Namespace the Secret lives in. Only a ClusterSecretStore may set this;
	// for a SecretStore, and for a ClusterSecretStore that leaves it empty,
	// the namespace of the referring ExternalSecret is used.
	// +optional
	// +kubebuilder:validation:MinLength:=1
	// +kubebuilder:validation:MaxLength:=63
	// +kubebuilder:validation:Pattern:=^[a-z0-9]([-a-z0-9]*[a-z0-9])?$
	Namespace *string `json:"namespace,omitempty"`
}
