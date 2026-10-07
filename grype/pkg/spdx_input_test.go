package pkg

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/internal/spdxfixture"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
)

func TestNormalizeSPDX3Context(t *testing.T) {
	const contextURL = "https://spdx.org/rdf/3.0.1/spdx-context.jsonld"

	tests := []struct {
		name      string
		input     string
		rewritten bool
	}{
		{name: "tag-value unchanged", input: "SPDXVersion: SPDX-2.2\n"},
		{name: "string context unchanged", input: `{"@context":"` + contextURL + `","@graph":[]}`},
		{name: "array context rewritten", input: `{"@context":["` + contextURL + `"],"name":"doc"}`, rewritten: true},
		{name: "unrelated array unchanged", input: `{"@context":["https://example.com/context.jsonld"]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeSPDX3Context([]byte(tt.input))
			if !tt.rewritten {
				require.Equal(t, tt.input, string(got))
				return
			}
			require.NotEqual(t, tt.input, string(got))
			require.Contains(t, string(got), `"`+contextURL+`"`)
			require.NotContains(t, string(got), `["`+contextURL+`"]`)
		})
	}
}

func TestSPDXDocumentsDecodeAtDeclaredVersion(t *testing.T) {
	for _, sample := range spdxfixture.Samples(t) {
		t.Run(sample.Name, func(t *testing.T) {
			if sample.ArrayContext {
				_, _, _, err := format.Decode(bytes.NewReader(sample.Body))
				require.Error(t, err)
			}

			prepared, err := prepareSBOMReader(bytes.NewReader(sample.Body))
			require.NoError(t, err)

			decoded, id, version, err := format.Decode(prepared)
			require.NoError(t, err)
			require.NotNil(t, decoded)
			require.Equal(t, sbom.FormatID(sample.FormatID), id)
			require.Equal(t, sample.Version, version)
			require.Equal(t, len(spdxfixture.ExpectedPackages()), decoded.Artifacts.Packages.PackageCount())
		})
	}
}

func TestSPDXDocumentsProvidePackages(t *testing.T) {
	for _, sample := range spdxfixture.Samples(t) {
		t.Run(sample.Name, func(t *testing.T) {
			pkgs, ctx, _, err := ProvideFromReader(bytes.NewReader(sample.Body), ProviderConfig{})
			require.NoError(t, err)
			assertSPDXPackages(t, pkgs)
			require.NotNil(t, ctx.Distro)
			require.Equal(t, "alpine", string(ctx.Distro.Type))
			require.Contains(t, ctx.Distro.Version, "3.12")
		})
	}
}
