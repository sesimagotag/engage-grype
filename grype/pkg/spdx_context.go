package pkg

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

// spdx3ContextPattern matches the SPDX 3.0 JSON-LD context URL. The patch
// component is optional: both 3.0 and 3.0.1 are published.
var spdx3ContextPattern = regexp.MustCompile(`^https://spdx\.org/rdf/3\.0(\.\d+)?/spdx-context\.jsonld$`)

// prepareSBOMReader returns an SBOM reader Syft can identify. SPDX 3 JSON-LD
// allows @context to be either a string or an array; Syft only identifies the
// string form, so an array context is rewritten to the SPDX context URL.
func prepareSBOMReader(reader io.ReadSeeker) (io.ReadSeeker, error) {
	if reader == nil {
		return nil, fmt.Errorf("no SBOM bytes provided")
	}

	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed reading SBOM: %w", err)
	}

	normalized := normalizeSPDX3Context(data)
	return bytes.NewReader(dropUnresolvedSPDX3Relationships(normalized)), nil
}

func normalizeSPDX3Context(data []byte) []byte {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return data
	}

	var doc map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &doc); err != nil {
		return data
	}

	url, ok := spdx3ContextURL(doc["@context"])
	if !ok {
		return data
	}

	encoded, err := json.Marshal(url)
	if err != nil {
		return data
	}
	doc["@context"] = encoded

	out, err := json.Marshal(doc)
	if err != nil {
		return data
	}
	return out
}

func spdx3ContextURL(raw json.RawMessage) (string, bool) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || raw[0] != '[' {
		return "", false
	}

	var entries []json.RawMessage
	if err := json.Unmarshal(raw, &entries); err != nil {
		return "", false
	}

	for _, entry := range entries {
		var url string
		if err := json.Unmarshal(entry, &url); err != nil {
			continue
		}
		if spdx3ContextPattern.MatchString(url) {
			return url, true
		}
	}
	return "", false
}
