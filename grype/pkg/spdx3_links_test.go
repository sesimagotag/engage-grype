package pkg

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDropUnresolvedSPDX3Relationships(t *testing.T) {
	const input = `{
		"@context": "https://spdx.org/rdf/3.0.1/spdx-context.jsonld",
		"@graph": [
			{"spdxId": "urn:local", "type": "software_Package", "name": "pkg"},
			{"type": "Relationship", "from": "urn:local", "to": ["urn:missing", "urn:local"]},
			{"type": "Relationship", "from": "urn:external", "to": ["urn:local"]}
		]
	}`

	var doc struct {
		Graph []map[string]any `json:"@graph"`
	}
	require.NoError(t, json.Unmarshal(dropUnresolvedSPDX3Relationships([]byte(input)), &doc))
	require.Len(t, doc.Graph, 2)
	require.Equal(t, "urn:local", doc.Graph[1]["from"])
	require.Equal(t, []any{"urn:local"}, doc.Graph[1]["to"])
}
