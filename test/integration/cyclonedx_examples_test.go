package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/internal/cyclonedxfixture"
	"github.com/anchore/syft/syft/source"
)

func TestCycloneDXDocumentsScan(t *testing.T) {
	provider := newSPDXMockDBProvider()
	for _, doc := range cyclonedxfixture.AllDocuments(t) {
		t.Run(doc.Name, func(t *testing.T) {
			matches, _, _, err := grype.FindVulnerabilities(provider, "sbom:"+doc.Path, source.SquashedScope, nil)
			require.NoError(t, err)
			require.NotNil(t, matches.Sorted())
		})
	}
}
