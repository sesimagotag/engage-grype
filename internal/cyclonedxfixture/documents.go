package cyclonedxfixture

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	FormatJSON = "cyclonedx-json"
	FormatXML  = "cyclonedx-xml"
)

var Versions = []string{"1.0", "1.1", "1.2", "1.3", "1.4", "1.5", "1.6", "1.7"}

// Document is one official CycloneDX specification or bom-examples document.
type Document struct {
	Corpus   string
	Version  string
	FormatID string
	Path     string
	Name     string
}

// SpecificationDocuments returns the canonical valid BOM for every
// specification version and serialization Grype supports: XML 1.0 through
// 1.7 and JSON 1.2 through 1.7.
func SpecificationDocuments(t testing.TB) []Document {
	t.Helper()

	root := repositoryDir(t, "cyclonedx-specification")
	resourceRoot := filepath.Join(root, "tools", "src", "test", "resources")
	var docs []Document
	for _, version := range Versions {
		docs = append(docs, specificationDocument(t, resourceRoot, version, "xml", FormatXML))
		if version != "1.0" && version != "1.1" {
			docs = append(docs, specificationDocument(t, resourceRoot, version, "json", FormatJSON))
		}
	}
	sortDocuments(docs)
	return docs
}

// BOMExampleDocuments returns every JSON and XML document from the official
// CycloneDX bom-examples repository.
func BOMExampleDocuments(t testing.TB) []Document {
	t.Helper()

	root := repositoryDir(t, "cyclonedx-bom-examples")
	var docs []Document
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}

		formatID := ""
		switch strings.ToLower(filepath.Ext(path)) {
		case ".json":
			formatID = FormatJSON
		case ".xml":
			formatID = FormatXML
		default:
			return nil
		}

		version, err := documentVersion(path, formatID)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		docs = append(docs, Document{
			Corpus:   "bom-examples",
			Version:  version,
			FormatID: formatID,
			Path:     path,
			Name:     filepath.ToSlash(filepath.Join("bom-examples", rel)),
		})
		return nil
	})
	require.NoError(t, err)
	require.NotEmpty(t, docs)
	sortDocuments(docs)
	return docs
}

func AllDocuments(t testing.TB) []Document {
	t.Helper()

	docs := append(SpecificationDocuments(t), BOMExampleDocuments(t)...)
	sortDocuments(docs)
	return docs
}

func specificationDocument(t testing.TB, root, version, extension, formatID string) Document {
	t.Helper()

	name := fmt.Sprintf("valid-bom-%s.%s", version, extension)
	path := filepath.Join(root, version, name)
	info, err := os.Stat(path)
	require.NoError(t, err)
	require.False(t, info.IsDir())
	return Document{
		Corpus:   "specification",
		Version:  version,
		FormatID: formatID,
		Path:     path,
		Name:     filepath.ToSlash(filepath.Join("specification", version, name)),
	}
}

func documentVersion(path, formatID string) (string, error) {
	raw, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer raw.Close()

	switch formatID {
	case FormatJSON:
		var doc struct {
			BOMFormat   string `json:"bomFormat"`
			SpecVersion string `json:"specVersion"`
		}
		if err := json.NewDecoder(raw).Decode(&doc); err != nil {
			return "", fmt.Errorf("decode CycloneDX JSON metadata from %s: %w", path, err)
		}
		if doc.BOMFormat != "CycloneDX" || doc.SpecVersion == "" {
			return "", fmt.Errorf("%s is not a versioned CycloneDX JSON document", path)
		}
		return doc.SpecVersion, nil
	case FormatXML:
		var doc struct {
			XMLNS string `xml:"xmlns,attr"`
		}
		if err := xml.NewDecoder(raw).Decode(&doc); err != nil {
			return "", fmt.Errorf("decode CycloneDX XML metadata from %s: %w", path, err)
		}
		const namespace = "http://cyclonedx.org/schema/bom/"
		version := strings.TrimPrefix(doc.XMLNS, namespace)
		if version == doc.XMLNS || version == "" {
			return "", fmt.Errorf("%s is not a versioned CycloneDX XML document", path)
		}
		return version, nil
	default:
		return "", fmt.Errorf("unsupported CycloneDX fixture format %q", formatID)
	}
}

func repositoryDir(t testing.TB, name string) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		candidate := filepath.Join(dir, "test", name)
		info, statErr := os.Stat(candidate)
		if statErr == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("%s submodule is missing; run git submodule update --init test/%s", name, name)
		}
		dir = parent
	}
}

func sortDocuments(docs []Document) {
	sort.Slice(docs, func(i, j int) bool {
		return docs[i].Name < docs[j].Name
	})
}
