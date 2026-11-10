package pkg

import (
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/internal/cyclonedxfixture"
	"github.com/anchore/syft/syft/format"
	"github.com/anchore/syft/syft/format/cyclonedxjson"
	"github.com/anchore/syft/syft/format/cyclonedxxml"
	"github.com/anchore/syft/syft/sbom"
)

func TestCycloneDXSpecificationDocuments(t *testing.T) {
	require.ElementsMatch(t, cyclonedxfixture.Versions, cyclonedxxml.SupportedVersions())
	require.ElementsMatch(t, cyclonedxfixture.Versions[2:], cyclonedxjson.SupportedVersions())

	docs := cyclonedxfixture.SpecificationDocuments(t)
	require.Len(t, docs, 14)

	seen := make(map[string]map[string]struct{})
	for _, doc := range docs {
		seenDocument(seen, doc)
		testCycloneDXDocument(t, doc)
	}

	for _, version := range cyclonedxfixture.Versions {
		require.Contains(t, seen[version], cyclonedxfixture.FormatXML)
		if version != "1.0" && version != "1.1" {
			require.Contains(t, seen[version], cyclonedxfixture.FormatJSON)
		}
	}
}

func TestCycloneDXBOMExampleDocuments(t *testing.T) {
	docs := cyclonedxfixture.BOMExampleDocuments(t)
	require.Len(t, docs, 83)

	for _, doc := range docs {
		testCycloneDXDocument(t, doc)
	}
}

func testCycloneDXDocument(t *testing.T, doc cyclonedxfixture.Document) {
	t.Helper()

	t.Run(doc.Name, func(t *testing.T) {
		raw, err := os.Open(doc.Path)
		require.NoError(t, err)
		t.Cleanup(func() { require.NoError(t, raw.Close()) })

		decoded, id, version, err := format.Decode(raw)
		require.NoError(t, err)
		require.NotNil(t, decoded)
		require.Equal(t, sbom.FormatID(doc.FormatID), id)
		require.Equal(t, doc.Version, version)

		_, err = raw.Seek(0, io.SeekStart)
		require.NoError(t, err)
		pkgs, _, provided, err := ProvideFromReader(raw, ProviderConfig{})
		require.NoError(t, err)
		require.NotNil(t, provided)
		if provided.Artifacts.Packages != nil && provided.Artifacts.Packages.PackageCount() > 0 {
			require.NotEmpty(t, pkgs)
		}
	})
}

func seenDocument(seen map[string]map[string]struct{}, doc cyclonedxfixture.Document) {
	if seen[doc.Version] == nil {
		seen[doc.Version] = make(map[string]struct{})
	}
	seen[doc.Version][doc.FormatID] = struct{}{}
}
