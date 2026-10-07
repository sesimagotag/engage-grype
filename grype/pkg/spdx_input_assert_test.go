package pkg

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/internal/spdxfixture"
	"github.com/anchore/packageurl-go"
)

func assertSPDXPackages(t *testing.T, pkgs []Package) {
	t.Helper()

	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}

	for _, want := range spdxfixture.ExpectedPackages() {
		got, ok := byName[want.Name]
		require.Truef(t, ok, "missing package %s", want.Name)
		require.Equal(t, want.Version, got.Version)
		require.Equal(t, want.Type, string(got.Type))
		require.Equal(t, mustPURL(t, want.PURL), mustPURL(t, got.PURL))
		if want.CPE != "" {
			require.NotEmpty(t, got.CPEs)
			require.Equal(t, want.CPE, got.CPEs[0].Attributes.String())
		}
		delete(byName, want.Name)
	}
	require.Empty(t, byName, "unexpected packages")
}

func mustPURL(t *testing.T, raw string) packageurl.PackageURL {
	t.Helper()
	parsed, err := packageurl.FromString(raw)
	require.NoError(t, err)
	return parsed
}
