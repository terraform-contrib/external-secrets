# Terraform / OpenTofu State

External Secrets Operator can read [Terraform](https://developer.hashicorp.com/terraform) and
[OpenTofu](https://opentofu.org) state directly, turning the root module outputs of an existing
state file into Kubernetes Secrets.

This is useful when a value only exists because Terraform created it — a generated database
password, an access key minted for an application, a connection string assembled from several
resources — and you would otherwise have to copy it into a secret manager by hand or with a
glue job.

The provider is **read only**. The state belongs to Terraform, and ESO never writes to it.
`PushSecret` against a Terraform state store always fails.

!!! warning "State files are sensitive in their entirety"
    Terraform writes resource attributes to state in plain text, including ones marked
    `sensitive` in the configuration. Anything that can read the state can read every value in
    it. Scope the credentials you give ESO to exactly the state objects it needs, and prefer a
    dedicated bucket prefix or Secret over a shared one.

## Addressing values

The provider exposes **root module outputs** only.

Outputs are the interface a Terraform configuration publishes for other consumers — it is what
the `terraform_remote_state` data source reads, and what `terraform output` prints. Resource
attributes are deliberately not addressable: their names are an implementation detail that
changes when you refactor, and reading them would couple your Secrets to the internal shape of
someone else's module. If you need a value that is not an output today, add one:

```hcl
output "db_password" {
  value     = random_password.db.result
  sensitive = true
}
```

| Field | Meaning |
| --- | --- |
| `remoteRef.key` | The name of a root module output. |
| `remoteRef.property` | Optional [gjson path](https://github.com/tidwall/gjson/blob/master/SYNTAX.md) into the output value. |

Values are rendered as follows:

* An output of type `string` lands in the Secret verbatim.
* Every other type — number, bool, list, object — is stored as its JSON encoding.
* An output whose type is `string` but whose content is JSON can still be descended into with
  `property`.

An output that does not exist is reported as a missing secret, so `deletionPolicy` behaves the
way it does for every other provider. A `property` that does not resolve is a hard error,
because that is a mistake in the ExternalSecret rather than a missing value.

`remoteRef.version` is not supported: a state backend only ever serves the current state.

## Creating a SecretStore

Exactly one backend must be configured. The backend settings mirror the
[Terraform backend block](https://developer.hashicorp.com/terraform/language/backend) of the
configuration that wrote the state.

### S3

```yaml
{% include 'terraform-secret-store-s3.yaml' %}
```

Authentication reuses the [AWS provider](./aws-access.md) credential resolution, so a
`secretRef`, a service account (`jwt`), or the SDK default chain all work the same way they do
for AWS Secrets Manager. The IAM identity needs `s3:GetObject` on the state object.

For a non-default workspace, include the workspace key prefix in `key`, exactly as it appears
in the bucket — by default that is `env:/<workspace>/<key>`.

Set `endpoint` and `forcePathStyle: true` to read from an S3-compatible store such as MinIO
or Ceph.

### HTTP

```yaml
{% include 'terraform-secret-store-http.yaml' %}
```

This covers the [`http` backend](https://developer.hashicorp.com/terraform/language/backend/http)
and the services that implement it, such as GitLab-managed Terraform state. The provider issues
a plain `GET` against `url` and expects the state document as the response body. `basic` and
`bearer` auth are supported, as is a custom CA through `caBundle` or `caProvider`.

### Kubernetes

```yaml
{% include 'terraform-secret-store-kubernetes.yaml' %}
```

Reads state written by the
[`kubernetes` backend](https://developer.hashicorp.com/terraform/language/backend/kubernetes),
which stores it in a Secret named `tfstate-{workspace}-{secretSuffix}`. The base64/gzip
encoding that backend applies is handled transparently.

`namespace` may only be set on a `ClusterSecretStore`. A `SecretStore`, and a
`ClusterSecretStore` that omits it, read from the namespace of the referring ExternalSecret.

## Referent authentication

On a `ClusterSecretStore`, any reference that omits `namespace` — a credential
`secretRef`, a `caProvider`, or the `kubernetes` backend's Secret — resolves in
the namespace of each referring ExternalSecret. Because there is no such
namespace while the store itself is validated, store validation is skipped for
these stores and any misconfiguration surfaces on the ExternalSecret instead.

## Restricting reads to sensitive outputs

Set `sensitiveOnly: true` on the provider to expose only outputs declared with
`sensitive = true`. Non-sensitive outputs then behave as if they did not exist. This is a
useful guard rail when the state is shared and you want an ExternalSecret with a broad
`dataFrom.find` to pick up secrets rather than every piece of infrastructure metadata.

## Creating an ExternalSecret

```yaml
{% include 'terraform-external-secret.yaml' %}
```

`dataFrom` works too — `extract` expands an object output into one Secret key per field, and
`find` selects outputs by name:

```yaml
{% include 'terraform-external-secret-datafrom.yaml' %}
```

`find.path` matches outputs whose name starts with the given prefix, and `find.name.regexp`
matches against the output name. `find.tags` is not supported, because state outputs carry no
tags.

## Refresh behaviour

The state is fetched once per reconcile and reused across every key in an ExternalSecret, so a
Secret with twenty keys costs one `GetObject`. Pick `refreshInterval` with the size of your
state file in mind.

## Limitations

* Root module outputs only, as described above.
* OpenTofu [state encryption](https://opentofu.org/docs/language/state/encryption/) is not
  supported. Encrypted state is detected and reported as an error rather than being silently
  skipped.
* State version 4 or newer (Terraform 0.12+, every OpenTofu release).
* Read only — no `PushSecret`.
