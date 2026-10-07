package spdxfixture

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const Version23 = "2.3"

// ExampleDocument is one SPDX file from the spdx-examples software submodule.
type ExampleDocument struct {
	Example  string
	Version  string
	FormatID string
	Path     string
	Name     string
}

// ExampleDocuments returns every SPDX 2.2, 2.3, and 3.0 document under
// software/example1 through software/example14.
func ExampleDocuments(t testing.TB) []ExampleDocument {
	t.Helper()

	root := softwareExamplesDir(t)
	var docs []ExampleDocument
	for n := 1; n <= 14; n++ {
		example := "example" + strconv.Itoa(n)
		docs = append(docs, documentsInExample(t, root, example)...)
	}
	require.NotEmpty(t, docs)
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].Name < docs[j].Name
	})
	return docs
}

func softwareExamplesDir(t testing.TB) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		candidate := filepath.Join(dir, "test", "spdx-examples", "software")
		info, statErr := os.Stat(candidate)
		if statErr == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("spdx-examples submodule is missing; run git submodule update --init test/spdx-examples")
		}
		dir = parent
	}
}

func documentsInExample(t testing.TB, root, example string) []ExampleDocument {
	t.Helper()

	exampleDir := filepath.Join(root, example)
	info, err := os.Stat(exampleDir)
	require.NoError(t, err)
	require.True(t, info.IsDir(), example)

	var docs []ExampleDocument
	for dirName, version := range map[string]string{
		"spdx2.2": Version22,
		"spdx2.3": Version23,
		"spdx3.0": Version30,
	} {
		versionDir := filepath.Join(exampleDir, dirName)
		entries, err := os.ReadDir(versionDir)
		if os.IsNotExist(err) {
			continue
		}
		require.NoError(t, err)
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			formatID, ok := spdxFormat(entry.Name())
			if !ok {
				continue
			}
			rel := filepath.Join(example, dirName, entry.Name())
			docs = append(docs, ExampleDocument{
				Example:  example,
				Version:  version,
				FormatID: formatID,
				Path:     filepath.Join(versionDir, entry.Name()),
				Name:     filepath.ToSlash(rel),
			})
		}
	}
	require.NotEmpty(t, docs, example)
	return docs
}

func spdxFormat(name string) (string, bool) {
	switch {
	case strings.HasSuffix(name, ".sha256"):
		return "", false
	case strings.HasSuffix(name, ".spdx.json"), strings.HasSuffix(name, ".spdx3.json"):
		return FormatJSON, true
	case strings.HasSuffix(name, ".spdx"):
		return FormatTagValue, true
	default:
		return "", false
	}
}
