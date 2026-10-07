package cli

import (
	"bytes"
	"os"
	"testing"

	"github.com/anchore/grype/internal/dbtest"
	"github.com/anchore/grype/internal/spdxfixture"
)

func TestSPDXExampleInput(t *testing.T) {
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

	for _, doc := range spdxfixture.ExampleDocuments(t) {
		t.Run(doc.Name, func(t *testing.T) {
			body, err := os.ReadFile(doc.Path)
			if err != nil {
				t.Fatal(err)
			}

			t.Run("sbom prefix", func(t *testing.T) {
				assertSPDXExampleScan(t, env, nil, "sbom:"+doc.Path)
			})
			t.Run("implicit path", func(t *testing.T) {
				assertSPDXExampleScan(t, env, nil, doc.Path)
			})
			t.Run("stdin", func(t *testing.T) {
				assertSPDXExampleScan(t, env, body)
			})
		})
	}
}

func assertSPDXExampleScan(t *testing.T, env map[string]string, stdin []byte, args ...string) {
	t.Helper()

	cmd := getGrypeCommand(t, append([]string{"-o", "json"}, args...)...)
	cmd.Env = append(os.Environ(), envMapToSlice(env)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}

	stdout, stderr := runCommand(cmd, nil)
	assertSucceedingReturnCode(t, stdout, stderr, cmd.ProcessState.ExitCode())
	assertJsonReport(t, stdout, stderr, cmd.ProcessState.ExitCode())
}
