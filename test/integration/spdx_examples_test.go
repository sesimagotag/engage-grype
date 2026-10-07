package integration

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/internal/spdxfixture"
	"github.com/anchore/syft/syft/source"
)

func TestSPDXExampleDocumentsScan(t *testing.T) {
	provider := newMockDbProvider()
	for _, doc := range spdxfixture.ExampleDocuments(t) {
		t.Run(doc.Name, func(t *testing.T) {
			matches, _, _, err := grype.FindVulnerabilities(provider, "sbom:"+doc.Path, source.SquashedScope, nil)
			require.NoError(t, err)
			require.NotNil(t, matches.Sorted())
		})
	}
}
