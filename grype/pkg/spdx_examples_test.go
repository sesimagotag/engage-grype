package pkg

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/internal/spdxfixture"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/sbom"
)

func TestSPDXExamplesDecode(t *testing.T) {
	docs := spdxfixture.ExampleDocuments(t)
	seenExamples := map[string]struct{}{}
	seenVersions := map[string]struct{}{}

	for _, doc := range docs {
		seenExamples[doc.Example] = struct{}{}
		seenVersions[doc.Version] = struct{}{}

		t.Run(doc.Name, func(t *testing.T) {
			raw, err := os.Open(doc.Path)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })

			prepared, err := prepareSBOMReader(raw)
			require.NoError(t, err)

			decoded, id, version, err := format.Decode(prepared)
			require.NoError(t, err)
			require.NotNil(t, decoded)
			require.Equal(t, sbom.FormatID(doc.FormatID), id)
			require.Equal(t, doc.Version, version)
		})
	}

	require.Len(t, seenExamples, 14)
	for _, version := range []string{spdxfixture.Version22, spdxfixture.Version23, spdxfixture.Version30} {
		_, ok := seenVersions[version]
		require.Truef(t, ok, "software examples include no SPDX %s document", version)
	}
}

func TestSPDXExamplesProvidePackages(t *testing.T) {
	for _, doc := range spdxfixture.ExampleDocuments(t) {
		t.Run(doc.Name, func(t *testing.T) {
			raw, err := os.Open(doc.Path)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, raw.Close()) })

			pkgs, _, decoded, err := ProvideFromReader(raw, ProviderConfig{})
			require.NoError(t, err)
			require.NotNil(t, decoded)
			if decoded.Artifacts.Packages != nil && decoded.Artifacts.Packages.PackageCount() > 0 {
				require.NotEmpty(t, pkgs)
			}
		})
	}
}
