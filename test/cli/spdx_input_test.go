package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/grype/internal/spdxfixture"
)

func TestSPDXInput(t *testing.T) {
	dbDir := t.TempDir()
	server := dbtest.NewServer(t)
	server.Vulnerabilities = spdxScanVulnerabilities()
	updateURL := server.Start()

	env := map[string]string{
		"GRYPE_DB_CACHE_DIR":   dbDir,
		"GRYPE_DB_UPDATE_URL":  updateURL,
		"GRYPE_DB_AUTO_UPDATE": "false",
	}
	update, stdout, stderr := runGrype(t, env, "db", "update")
	assertSucceedingReturnCode(t, stdout, stderr, update.ProcessState.ExitCode())

	for _, sample := range spdxfixture.Samples(t) {
		t.Run(sample.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sbom"+sample.Extension)
			require.NoError(t, os.WriteFile(path, sample.Body, 0o600))

			t.Run("sbom prefix", func(t *testing.T) {
				assertSPDXScan(t, env, nil, "sbom:"+path)
			})
			t.Run("implicit path", func(t *testing.T) {
				assertSPDXScan(t, env, nil, path)
			})
			t.Run("stdin", func(t *testing.T) {
				assertSPDXScan(t, env, sample.Body)
			})
		})
	}
}

func assertSPDXScan(t *testing.T, env map[string]string, stdin []byte, args ...string) {
	t.Helper()

	cmd := getGrypeCommand(t, append([]string{"-o", "json"}, args...)...)
	cmd.Env = append(os.Environ(), envMapToSlice(env)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	stdout, stderr := runCommand(cmd, nil)
	assertSucceedingReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())
	assertJsonReport(t, stdout, stderr, cmd.ProcessState.ExitCode())
	// Java coordinates are covered by the in-process SPDX match test. The v6
	// fixture DB stores a language feed under the language name, which does
	// not line up with the java-archive package type.
	for _, id := range []string{"CVE-python-pygments", "CVE-2024-0000"} {
		require.Contains(t, stdout, id)
	}
}

func spdxScanVulnerabilities() []vulnerability.Vulnerability {
	return []vulnerability.Vulnerability{
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-python-pygments",
				Namespace: "github:language:python",
			},
			PackageName: "pygments",
			Constraint:  version.MustGetConstraint("< 2.6.2", version.PythonFormat),
		},
		{
			Reference: vulnerability.Reference{
				ID:        "CVE-2024-0000",
				Namespace: "alpine:distro:alpine:3.12",
			},
			PackageName: "libvncserver",
			Constraint:  version.MustGetConstraint("< 0.9.10", version.ApkFormat),
		},
	}
}
