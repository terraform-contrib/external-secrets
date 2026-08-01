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
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testState is a trimmed but structurally faithful version 4 state.
const testState = `{
  "version": 4,
  "terraform_version": "1.9.8",
  "serial": 7,
  "lineage": "8d1a2f2c-0000-4000-8000-2f0e5b6c7d8e",
  "outputs": {
    "db_password": {"value": "s3cr3t", "type": "string", "sensitive": true},
    "db_endpoint": {"value": "db.internal:5432", "type": "string"},
    "api_keys": {"value": {"alpha": "key-a", "beta": "key-b"}, "type": ["object", {"alpha": "string", "beta": "string"}], "sensitive": true},
    "replica_count": {"value": 3, "type": "number"},
    "zones": {"value": ["eu-west-1a", "eu-west-1b"], "type": ["list", "string"]},
    "connection.string": {"value": "postgres://db", "type": "string"},
    "json_blob": {"value": "{\"nested\":\"inner\"}", "type": "string", "sensitive": true}
  },
  "resources": []
}`

func gzipBytes(t *testing.T, in []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, err := zw.Write(in)
	require.NoError(t, err)
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

func TestDecodeState(t *testing.T) {
	plain := []byte(`{"version":4}`)

	tests := []struct {
		name    string
		in      []byte
		want    []byte
		wantErr string
	}{
		{
			name: "plain json",
			in:   plain,
			want: plain,
		},
		{
			name: "json with surrounding whitespace",
			in:   []byte("\n  " + string(plain) + "\n"),
			want: plain,
		},
		{
			name: "gzip",
			in:   gzipBytes(t, plain),
			want: plain,
		},
		{
			name: "base64 of gzip, as the kubernetes backend writes it",
			in:   []byte(base64.StdEncoding.EncodeToString(gzipBytes(t, plain))),
			want: plain,
		},
		{
			name: "base64 of plain json",
			in:   []byte(base64.StdEncoding.EncodeToString(plain)),
			want: plain,
		},
		{
			name:    "empty",
			in:      []byte("   "),
			wantErr: "state is empty",
		},
		{
			name:    "not json, gzip or base64",
			in:      []byte("!! not a state !!"),
			wantErr: "neither JSON, gzip nor base64",
		},
		{
			name:    "base64 of something else",
			in:      []byte(base64.StdEncoding.EncodeToString([]byte("hello there"))),
			wantErr: "does not decode to JSON or gzip",
		},
		{
			name:    "gzip with a truncated header",
			in:      gzipBytes(t, plain)[:8],
			wantErr: "cannot read gzipped state",
		},
		{
			name: "gzip with a truncated body",
			in: func() []byte {
				full := gzipBytes(t, plain)
				return full[:len(full)-5]
			}(),
			wantErr: "cannot decompress state",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := decodeState(tt.in)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, string(tt.want), string(got))
		})
	}
}

func TestParseState(t *testing.T) {
	t.Run("parses outputs and sensitivity", func(t *testing.T) {
		st, err := parseState([]byte(testState))
		require.NoError(t, err)
		assert.Equal(t, 4, st.Version)
		assert.Len(t, st.Outputs, 7)
		assert.True(t, st.Outputs["db_password"].Sensitive)
		assert.False(t, st.Outputs["db_endpoint"].Sensitive)
	})

	t.Run("accepts a gzipped state", func(t *testing.T) {
		st, err := parseState(gzipBytes(t, []byte(testState)))
		require.NoError(t, err)
		assert.Len(t, st.Outputs, 7)
	})

	t.Run("rejects an old state version", func(t *testing.T) {
		_, err := parseState([]byte(`{"version":3,"modules":[]}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported state version 3")
	})

	t.Run("rejects encrypted OpenTofu state", func(t *testing.T) {
		_, err := parseState([]byte(`{"encrypted_data":"AAAA","encryption_version":"v0"}`))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "state is encrypted")
	})

	t.Run("rejects malformed json", func(t *testing.T) {
		_, err := parseState([]byte(`{"version": `))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "not valid JSON")
	})
}

func TestRenderValue(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "string is unquoted", in: `"s3cr3t"`, want: "s3cr3t"},
		{name: "string keeps its escapes decoded", in: `"a\"b"`, want: `a"b`},
		{name: "number keeps json form", in: `3`, want: "3"},
		{name: "bool keeps json form", in: `true`, want: "true"},
		{name: "object keeps json form", in: `{"a":"b"}`, want: `{"a":"b"}`},
		{name: "list keeps json form", in: `["a","b"]`, want: `["a","b"]`},
		{name: "null keeps json form", in: `null`, want: "null"},
		{name: "empty raw", in: ``, want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, string(renderValue(json.RawMessage(tt.in))))
		})
	}
}

func TestGunzipRejectsOversizedState(t *testing.T) {
	// A highly compressible payload that expands past the cap.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	chunk := bytes.Repeat([]byte("a"), 1<<20)
	for range (maxDecompressedStateSize / len(chunk)) + 1 {
		_, err := zw.Write(chunk)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())

	_, err := gunzip(buf.Bytes())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds the")
}
