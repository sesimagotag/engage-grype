package integration

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/scylladb/go-set/strset"
	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype"
	"github.com/anchore/grype/internal/spdxfixture"
	"github.com/anchore/syft/syft/source"
)

func TestSPDXSBOMMatches(t *testing.T) {
	want := strset.New(
		"CVE-python-pygments",
		"CVE-2024-0000",
		"CVE-java-example-java-app",
	)

	for _, sample := range spdxfixture.Samples(t) {
		t.Run(sample.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sbom"+sample.Extension)
			require.NoError(t, os.WriteFile(path, sample.Body, 0o600))

			matches, _, _, err := grype.FindVulnerabilities(newMockDbProvider(), "sbom:"+path, source.SquashedScope, nil)
			require.NoError(t, err)

			got := strset.New()
			for _, m := range matches.Sorted() {
				got.Add(m.Vulnerability.ID)
			}
			require.ElementsMatch(t, want.List(), got.List())
		})
	}
}
