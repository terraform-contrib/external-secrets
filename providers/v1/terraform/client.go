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
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/tidwall/gjson"
	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

// errReadOnly is returned by every write path. The state belongs to Terraform;
// ESO must never be the thing that changes it.
var errReadOnly = errors.New("the Terraform state provider is read-only, the state is owned by Terraform / OpenTofu")

// validateTimeout bounds the state fetch performed by Validate, which the
// controller calls synchronously.
const validateTimeout = 15 * time.Second

// Client reads root module outputs out of a single Terraform / OpenTofu state.
type Client struct {
	fetch         fetcher
	sensitiveOnly bool

	// referent marks a client built for a ClusterSecretStore that references
	// objects without an explicit namespace. Such references resolve in the
	// namespace of the referring ExternalSecret, so during store validation,
	// where no namespace exists, nothing can be fetched and Validate reports
	// Unknown instead of an error.
	referent bool

	// The state is fetched at most once per client. A client lives for a single
	// reconcile, so this collapses the N fetches an ExternalSecret with N keys
	// would otherwise cause, without ever serving a stale document.
	once    sync.Once
	state   *state
	loadErr error
}

var _ esv1.SecretsClient = &Client{}

func (c *Client) load(ctx context.Context) (*state, error) {
	c.once.Do(func() {
		raw, err := c.fetch(ctx)
		if err != nil {
			c.loadErr = err
			return
		}
		c.state, c.loadErr = parseState(raw)
	})
	return c.state, c.loadErr
}

// output looks up a root module output by name. A name that is absent, or that
// is filtered out by sensitiveOnly, yields esv1.NoSecretErr so that
// deletionPolicy behaves the way it does for every other provider.
func (c *Client) output(st *state, name string) (output, error) {
	out, ok := st.Outputs[name]
	if !ok {
		return output{}, esv1.NoSecretErr
	}
	if c.sensitiveOnly && !out.Sensitive {
		return output{}, esv1.NoSecretErr
	}
	return out, nil
}

// GetSecret returns the value of a single root module output.
func (c *Client) GetSecret(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) ([]byte, error) {
	if ref.Key == "" {
		return nil, errors.New("key is required and must name a root module output")
	}
	if ref.Version != "" {
		return nil, errors.New("version is not supported: a state backend only exposes the current state")
	}

	st, err := c.load(ctx)
	if err != nil {
		return nil, err
	}
	out, err := c.output(st, ref.Key)
	if err != nil {
		return nil, err
	}

	value := renderValue(out.Value)
	if ref.Property == "" {
		return value, nil
	}

	// Descend into the rendered value rather than the raw one, so that an
	// output whose type is `string` but whose content is JSON can be addressed
	// the same way an object output can.
	result := getProperty(value, ref.Property)
	if !result.Exists() {
		return nil, fmt.Errorf("property %q does not exist in output %q", ref.Property, ref.Key)
	}
	return renderValue(json.RawMessage(result.Raw)), nil
}

// GetSecretMap returns a map of key/value pairs.
//
// With an empty key it returns every readable output. With a key it returns the
// fields of that output, which must then be an object.
func (c *Client) GetSecretMap(ctx context.Context, ref esv1.ExternalSecretDataRemoteRef) (map[string][]byte, error) {
	if ref.Version != "" {
		return nil, errors.New("version is not supported: a state backend only exposes the current state")
	}

	st, err := c.load(ctx)
	if err != nil {
		return nil, err
	}

	if ref.Key == "" {
		if ref.Property != "" {
			return nil, errors.New("property requires a key naming a root module output")
		}
		values := make(map[string][]byte, len(st.Outputs))
		for name := range st.Outputs {
			out, err := c.output(st, name)
			if errors.Is(err, esv1.NoSecretErr) {
				continue
			} else if err != nil {
				return nil, err
			}
			values[name] = renderValue(out.Value)
		}
		return values, nil
	}

	raw, err := c.GetSecret(ctx, ref)
	if err != nil {
		return nil, err
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, fmt.Errorf("output %q is not an object, so it cannot be expanded into a secret map: %w", ref.Key, err)
	}
	// JSON null unmarshals into a nil map without an error; report it as the
	// non-object it is rather than silently producing an empty Secret.
	if fields == nil {
		return nil, fmt.Errorf("output %q is null, so it cannot be expanded into a secret map", ref.Key)
	}
	values := make(map[string][]byte, len(fields))
	for name, value := range fields {
		values[name] = renderValue(value)
	}
	return values, nil
}

// GetAllSecrets returns every output whose name matches the find criteria.
func (c *Client) GetAllSecrets(ctx context.Context, ref esv1.ExternalSecretFind) (map[string][]byte, error) {
	if len(ref.Tags) > 0 {
		return nil, errors.New("find by tags is not supported: state outputs carry no tags")
	}

	var matcher *regexp.Regexp
	if ref.Name != nil && ref.Name.RegExp != "" {
		var err error
		matcher, err = regexp.Compile(ref.Name.RegExp)
		if err != nil {
			return nil, fmt.Errorf("invalid name.regexp: %w", err)
		}
	}

	st, err := c.load(ctx)
	if err != nil {
		return nil, err
	}

	values := make(map[string][]byte)
	for name := range st.Outputs {
		if ref.Path != nil && !strings.HasPrefix(name, *ref.Path) {
			continue
		}
		if matcher != nil && !matcher.MatchString(name) {
			continue
		}
		out, err := c.output(st, name)
		if errors.Is(err, esv1.NoSecretErr) {
			continue
		} else if err != nil {
			return nil, err
		}
		values[name] = renderValue(out.Value)
	}
	return values, nil
}

// Validate fetches and parses the state so that a misconfigured store surfaces
// on the SecretStore itself rather than on every ExternalSecret using it.
func (c *Client) Validate() (esv1.ValidationResult, error) {
	// Referent references only resolve inside an ExternalSecret reconcile, so
	// there is nothing that can be checked here.
	if c.referent {
		return esv1.ValidationResultUnknown, nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), validateTimeout)
	defer cancel()

	if _, err := c.load(ctx); err != nil {
		return esv1.ValidationResultError, err
	}
	return esv1.ValidationResultReady, nil
}

// PushSecret is not supported: the state is owned by Terraform.
func (c *Client) PushSecret(context.Context, *corev1.Secret, esv1.PushSecretData) error {
	return errReadOnly
}

// DeleteSecret is not supported: the state is owned by Terraform.
func (c *Client) DeleteSecret(context.Context, esv1.PushSecretRemoteRef) error {
	return errReadOnly
}

// SecretExists is not supported: it only has meaning for the write path.
func (c *Client) SecretExists(context.Context, esv1.PushSecretRemoteRef) (bool, error) {
	return false, errReadOnly
}

// Close is a no-op, the client holds no long-lived resources.
func (c *Client) Close(context.Context) error {
	return nil
}

// getProperty resolves a gjson path against a rendered output value. Object
// keys routinely contain dots, so try the escaped path first and fall back to
// treating the dots as a path separator.
func getProperty(value []byte, property string) gjson.Result {
	if strings.Contains(property, ".") {
		if escaped := gjson.GetBytes(value, strings.ReplaceAll(property, ".", `\.`)); escaped.Exists() {
			return escaped
		}
	}
	return gjson.GetBytes(value, property)
}
