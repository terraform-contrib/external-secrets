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
	"errors"
	"fmt"
	"io"
)

// minStateVersion is the oldest state format that stores root module outputs at
// the top level. Terraform writes it since 0.12, OpenTofu has only ever written it.
const minStateVersion = 4

// maxDecompressedStateSize bounds the state we are willing to hold in memory
// after decompression, so that a hostile or corrupt backend cannot exhaust it.
const maxDecompressedStateSize = 128 << 20 // 128 MiB

var gzipMagic = []byte{0x1f, 0x8b}

// state is the subset of the Terraform / OpenTofu state document this provider reads.
type state struct {
	Version int               `json:"version"`
	Outputs map[string]output `json:"outputs"`

	// EncryptedData is set when OpenTofu wrote the state with state encryption
	// enabled. The outputs are unreadable in that case.
	EncryptedData json.RawMessage `json:"encrypted_data"`
}

// output is a single root module output as recorded in the state.
type output struct {
	Value     json.RawMessage `json:"value"`
	Sensitive bool            `json:"sensitive"`
}

// parseState decodes and validates a raw state document.
func parseState(raw []byte) (*state, error) {
	decoded, err := decodeState(raw)
	if err != nil {
		return nil, err
	}

	var st state
	if err := json.Unmarshal(decoded, &st); err != nil {
		return nil, fmt.Errorf("state is not valid JSON: %w", err)
	}

	if len(st.EncryptedData) > 0 {
		return nil, errors.New("state is encrypted: ESO cannot read OpenTofu encrypted state, expose the values through an unencrypted backend or a secret manager instead")
	}
	if st.Version < minStateVersion {
		return nil, fmt.Errorf("unsupported state version %d, this provider requires version %d or newer (Terraform 0.12+ / OpenTofu)", st.Version, minStateVersion)
	}

	return &st, nil
}

// decodeState unwraps the transport encodings a backend may have applied to the
// state document. The Kubernetes backend stores it base64-encoded gzip, while
// the S3 and HTTP backends serve it as plain JSON. Rather than tying the
// decoding to the backend, sniff it, so that the same code handles a backend
// that changes its encoding between Terraform releases.
func decodeState(raw []byte) ([]byte, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return nil, errors.New("state is empty")
	}

	// Plain JSON, the common case.
	if trimmed[0] == '{' {
		return trimmed, nil
	}

	if bytes.HasPrefix(trimmed, gzipMagic) {
		return gunzip(trimmed)
	}

	// Anything else is base64, which may in turn wrap gzip.
	inner, err := base64.StdEncoding.AppendDecode(nil, trimmed)
	if err != nil {
		return nil, fmt.Errorf("state is neither JSON, gzip nor base64: %w", err)
	}
	inner = bytes.TrimSpace(inner)
	if bytes.HasPrefix(inner, gzipMagic) {
		return gunzip(inner)
	}
	if len(inner) > 0 && inner[0] == '{' {
		return inner, nil
	}
	return nil, errors.New("state is base64 but does not decode to JSON or gzip")
}

func gunzip(in []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(in))
	if err != nil {
		return nil, fmt.Errorf("cannot read gzipped state: %w", err)
	}
	defer func() { _ = zr.Close() }()

	// Read one byte past the limit so that hitting it exactly is still an error
	// rather than a silently truncated document.
	out, err := io.ReadAll(io.LimitReader(zr, maxDecompressedStateSize+1))
	if err != nil {
		return nil, fmt.Errorf("cannot decompress state: %w", err)
	}
	if len(out) > maxDecompressedStateSize {
		return nil, fmt.Errorf("decompressed state exceeds the %d byte limit", maxDecompressedStateSize)
	}
	return out, nil
}

// renderValue turns an output value into the bytes ESO stores in the Secret.
// JSON strings are unquoted so that a `string` output lands in the Secret
// verbatim; every other type keeps its JSON encoding.
func renderValue(raw json.RawMessage) []byte {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return []byte{}
	}
	// Only a JSON string can start with a quote. Testing the first byte rather
	// than attempting an unmarshal keeps `null` out of the string branch, which
	// unmarshals into "" without erroring.
	if trimmed[0] == '"' {
		var s string
		if err := json.Unmarshal(trimmed, &s); err == nil {
			return []byte(s)
		}
	}
	return trimmed
}
