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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"

	esv1 "github.com/external-secrets/external-secrets/apis/externalsecrets/v1"
)

func testClient(sensitiveOnly bool) *Client {
	return &Client{
		fetch:         func(context.Context) ([]byte, error) { return []byte(testState), nil },
		sensitiveOnly: sensitiveOnly,
	}
}

func TestGetSecret(t *testing.T) {
	tests := []struct {
		name          string
		sensitiveOnly bool
		ref           esv1.ExternalSecretDataRemoteRef
		want          string
		wantErr       string
		wantNoSecret  bool
	}{
		{
			name: "string output",
			ref:  esv1.ExternalSecretDataRemoteRef{Key: "db_password"},
			want: "s3cr3t",
		},
		{
			name: "number output keeps its json form",
			ref:  esv1.ExternalSecretDataRemoteRef{Key: "replica_count"},
			want: "3",
		},
		{
			name: "object output keeps its json form",
			ref:  esv1.ExternalSecretDataRemoteRef{Key: "api_keys"},
			want: `{"alpha": "key-a", "beta": "key-b"}`,
		},
		{
			name: "property selects an object field",
			ref:  esv1.ExternalSecretDataRemoteRef{Key: "api_keys", Property: "alpha"},
			want: "key-a",
		},
		{
			name: "property selects a list element",
			ref:  esv1.ExternalSecretDataRemoteRef{Key: "zones", Property: "1"},
			want: "eu-west-1b",
		},
		{
			name:         "unknown output is NoSecretErr",
			ref:          esv1.ExternalSecretDataRemoteRef{Key: "nope"},
			wantNoSecret: true,
		},
		{
			name:          "non-sensitive output is hidden when sensitiveOnly is set",
			sensitiveOnly: true,
			ref:           esv1.ExternalSecretDataRemoteRef{Key: "db_endpoint"},
			wantNoSecret:  true,
		},
		{
			name:          "sensitive output is still readable when sensitiveOnly is set",
			sensitiveOnly: true,
			ref:           esv1.ExternalSecretDataRemoteRef{Key: "db_password"},
			want:          "s3cr3t",
		},
		{
			name:    "unknown property is an error, not a missing secret",
			ref:     esv1.ExternalSecretDataRemoteRef{Key: "api_keys", Property: "gamma"},
			wantErr: `property "gamma" does not exist in output "api_keys"`,
		},
		{
			name:    "empty key is rejected",
			ref:     esv1.ExternalSecretDataRemoteRef{},
			wantErr: "key is required",
		},
		{
			name:    "version is rejected rather than silently ignored",
			ref:     esv1.ExternalSecretDataRemoteRef{Key: "db_password", Version: "7"},
			wantErr: "version is not supported",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := testClient(tt.sensitiveOnly).GetSecret(t.Context(), tt.ref)
			switch {
			case tt.wantNoSecret:
				require.ErrorIs(t, err, esv1.NoSecretErr)
			case tt.wantErr != "":
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			default:
				require.NoError(t, err)
				assert.Equal(t, tt.want, string(got))
			}
		})
	}
}

// An output name that contains a dot must still be reachable, and a property
// path must be able to address a nested field.
func TestGetSecretDottedNames(t *testing.T) {
	c := testClient(false)

	got, err := c.GetSecret(t.Context(), esv1.ExternalSecretDataRemoteRef{Key: "connection.string"})
	require.NoError(t, err)
	assert.Equal(t, "postgres://db", string(got))

	// A string output holding JSON can be descended into.
	got, err = c.GetSecret(t.Context(), esv1.ExternalSecretDataRemoteRef{Key: "json_blob", Property: "nested"})
	require.NoError(t, err)
	assert.Equal(t, "inner", string(got))
}

func TestGetSecretPropagatesFetchError(t *testing.T) {
	sentinel := errors.New("backend unreachable")
	c := &Client{fetch: func(context.Context) ([]byte, error) { return nil, sentinel }}

	_, err := c.GetSecret(t.Context(), esv1.ExternalSecretDataRemoteRef{Key: "db_password"})
	require.ErrorIs(t, err, sentinel)
}

func TestStateIsFetchedOncePerClient(t *testing.T) {
	var calls int
	c := &Client{fetch: func(context.Context) ([]byte, error) {
		calls++
		return []byte(testState), nil
	}}

	for _, key := range []string{"db_password", "db_endpoint", "replica_count"} {
		_, err := c.GetSecret(t.Context(), esv1.ExternalSecretDataRemoteRef{Key: key})
		require.NoError(t, err)
	}
	assert.Equal(t, 1, calls, "the state should be fetched once and reused for the lifetime of the client")
}

func TestGetSecretMap(t *testing.T) {
	t.Run("empty key returns every output", func(t *testing.T) {
		got, err := testClient(false).GetSecretMap(t.Context(), esv1.ExternalSecretDataRemoteRef{})
		require.NoError(t, err)
		assert.Len(t, got, 7)
		assert.Equal(t, "s3cr3t", string(got["db_password"]))
		assert.Equal(t, "db.internal:5432", string(got["db_endpoint"]))
		assert.Equal(t, "3", string(got["replica_count"]))
	})

	t.Run("empty key honors sensitiveOnly", func(t *testing.T) {
		got, err := testClient(true).GetSecretMap(t.Context(), esv1.ExternalSecretDataRemoteRef{})
		require.NoError(t, err)
		assert.Len(t, got, 3)
		for _, name := range []string{"db_password", "api_keys", "json_blob"} {
			assert.Contains(t, got, name)
		}
	})

	t.Run("key expands an object output", func(t *testing.T) {
		got, err := testClient(false).GetSecretMap(t.Context(), esv1.ExternalSecretDataRemoteRef{Key: "api_keys"})
		require.NoError(t, err)
		assert.Equal(t, map[string][]byte{
			"alpha": []byte("key-a"),
			"beta":  []byte("key-b"),
		}, got)
	})

	t.Run("key expands a string output holding json", func(t *testing.T) {
		got, err := testClient(false).GetSecretMap(t.Context(), esv1.ExternalSecretDataRemoteRef{Key: "json_blob"})
		require.NoError(t, err)
		assert.Equal(t, map[string][]byte{"nested": []byte("inner")}, got)
	})

	t.Run("scalar output cannot be expanded", func(t *testing.T) {
		_, err := testClient(false).GetSecretMap(t.Context(), esv1.ExternalSecretDataRemoteRef{Key: "replica_count"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is not an object")
	})

	t.Run("property without a key is rejected", func(t *testing.T) {
		_, err := testClient(false).GetSecretMap(t.Context(), esv1.ExternalSecretDataRemoteRef{Property: "alpha"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "property requires a key")
	})

	t.Run("version is rejected", func(t *testing.T) {
		_, err := testClient(false).GetSecretMap(t.Context(), esv1.ExternalSecretDataRemoteRef{Version: "3"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "version is not supported")
	})

	t.Run("null output cannot be expanded", func(t *testing.T) {
		client := &Client{fetch: func(context.Context) ([]byte, error) {
			return []byte(`{"version": 4, "outputs": {"maybe": {"value": null, "type": "string"}}}`), nil
		}}
		_, err := client.GetSecretMap(t.Context(), esv1.ExternalSecretDataRemoteRef{Key: "maybe"})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "is null")
	})
}

func TestGetAllSecrets(t *testing.T) {
	tests := []struct {
		name          string
		sensitiveOnly bool
		ref           esv1.ExternalSecretFind
		wantKeys      []string
		wantErr       string
	}{
		{
			name:     "no filter returns everything",
			ref:      esv1.ExternalSecretFind{},
			wantKeys: []string{"db_password", "db_endpoint", "api_keys", "replica_count", "zones", "connection.string", "json_blob"},
		},
		{
			name:     "path filters by prefix",
			ref:      esv1.ExternalSecretFind{Path: new("db_")},
			wantKeys: []string{"db_password", "db_endpoint"},
		},
		{
			name:     "regexp filters by name",
			ref:      esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "^db_p"}},
			wantKeys: []string{"db_password"},
		},
		{
			name:     "path and regexp are combined",
			ref:      esv1.ExternalSecretFind{Path: new("db_"), Name: &esv1.FindName{RegExp: "point$"}},
			wantKeys: []string{"db_endpoint"},
		},
		{
			name:          "sensitiveOnly narrows the result",
			sensitiveOnly: true,
			ref:           esv1.ExternalSecretFind{Path: new("db_")},
			wantKeys:      []string{"db_password"},
		},
		{
			name:     "no match returns an empty map",
			ref:      esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "^nothing"}},
			wantKeys: []string{},
		},
		{
			name:    "tags are rejected",
			ref:     esv1.ExternalSecretFind{Tags: map[string]string{"env": "prod"}},
			wantErr: "find by tags is not supported",
		},
		{
			name:    "invalid regexp is reported",
			ref:     esv1.ExternalSecretFind{Name: &esv1.FindName{RegExp: "([a-z"}},
			wantErr: "invalid name.regexp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := testClient(tt.sensitiveOnly).GetAllSecrets(t.Context(), tt.ref)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)

			keys := make([]string, 0, len(got))
			for k := range got {
				keys = append(keys, k)
			}
			assert.ElementsMatch(t, tt.wantKeys, keys)
		})
	}
}

func TestValidate(t *testing.T) {
	t.Run("ready when the state can be read", func(t *testing.T) {
		result, err := testClient(false).Validate()
		require.NoError(t, err)
		assert.Equal(t, esv1.ValidationResultReady, result)
	})

	t.Run("error when the backend fails", func(t *testing.T) {
		c := &Client{fetch: func(context.Context) ([]byte, error) { return nil, errors.New("denied") }}
		result, err := c.Validate()
		require.Error(t, err)
		assert.Equal(t, esv1.ValidationResultError, result)
	})

	t.Run("error when the state cannot be parsed", func(t *testing.T) {
		c := &Client{fetch: func(context.Context) ([]byte, error) { return []byte(`{"version":3}`), nil }}
		result, err := c.Validate()
		require.Error(t, err)
		assert.Equal(t, esv1.ValidationResultError, result)
	})
}

// Every write path must fail loudly: returning nil would let a PushSecret
// silently report success against a store that can never accept one.
func TestWritePathsAreRejected(t *testing.T) {
	c := testClient(false)

	require.ErrorIs(t, c.PushSecret(t.Context(), &corev1.Secret{}, nil), errReadOnly)
	require.ErrorIs(t, c.DeleteSecret(t.Context(), nil), errReadOnly)

	exists, err := c.SecretExists(t.Context(), nil)
	require.ErrorIs(t, err, errReadOnly)
	assert.False(t, exists)

	require.NoError(t, c.Close(t.Context()))
}
