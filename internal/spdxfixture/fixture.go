package spdxfixture

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/cpe"
	"github.com/anchore/syft/syft/format/spdxjson"
	"github.com/anchore/syft/syft/format/spdxtagvalue"
	syftPkg "github.com/anchore/syft/syft/pkg"
	"github.com/anchore/syft/syft/sbom"
	"github.com/anchore/syft/syft/source"
)

const (
	FormatJSON     = "spdx-json"
	FormatTagValue = "spdx-tag-value"

	Version22 = "2.2"
	Version30 = "3.0"

	libvncCPE = "cpe:2.3:a:libvncserver:libvncserver:0.9.9:*:*:*:*:*:*:*"
)

// Sample is one SPDX document the scan tests feed to Grype.
type Sample struct {
	Name         string
	Version      string
	FormatID     string
	Extension    string
	Body         []byte
	ArrayContext bool
}

// PackageExpect is the package identity that must survive decoding.
type PackageExpect struct {
	Name    string
	Version string
	Type    string
	PURL    string
	CPE     string
}

// ExpectedPackages is the package set encoded into every sample.
func ExpectedPackages() []PackageExpect {
	return []PackageExpect{
		{Name: "pygments", Version: "2.6.1", Type: "python", PURL: "pkg:pypi/pygments@2.6.1"},
		{
			Name:    "libvncserver",
			Version: "0.9.9",
			Type:    "apk",
			PURL:    "pkg:apk/alpine/libvncserver@0.9.9?arch=x86_64&distro=alpine-3.12.0",
			CPE:     libvncCPE,
		},
		{
			Name:    "example-java-app-maven",
			Version: "0.1.0",
			Type:    "java-archive",
			PURL:    "pkg:maven/org.anchore/example-java-app-maven@0.1.0",
		},
	}
}

// Samples returns SPDX 2.2 and SPDX 3.0 documents for the same package set.
func Samples(t testing.TB) []Sample {
	t.Helper()

	document := catalog()
	json22 := encode(t, document, Version22, FormatJSON)
	tag22 := encode(t, document, Version22, FormatTagValue)
	json30 := encode(t, document, Version30, FormatJSON)

	return []Sample{
		{Name: "spdx-2.2-json-handwritten", Version: Version22, FormatID: FormatJSON, Extension: ".json", Body: []byte(handwrittenJSON22)},
		{Name: "spdx-2.2-tag-value-handwritten", Version: Version22, FormatID: FormatTagValue, Extension: ".spdx", Body: []byte(handwrittenTagValue22)},
		{Name: "spdx-2.2-json", Version: Version22, FormatID: FormatJSON, Extension: ".json", Body: json22},
		{Name: "spdx-2.2-tag-value", Version: Version22, FormatID: FormatTagValue, Extension: ".spdx", Body: tag22},
		{Name: "spdx-3.0-json", Version: Version30, FormatID: FormatJSON, Extension: ".json", Body: json30},
		{Name: "spdx-3.0-json-array-context", Version: Version30, FormatID: FormatJSON, Extension: ".json", Body: arrayContext(t, json30), ArrayContext: true},
	}
}

func catalog() sbom.SBOM {
	pkgs := []syftPkg.Package{
		{
			Name:     "pygments",
			Version:  "2.6.1",
			Type:     syftPkg.PythonPkg,
			Language: syftPkg.Python,
			PURL:     "pkg:pypi/pygments@2.6.1",
		},
		{
			Name:    "libvncserver",
			Version: "0.9.9",
			Type:    syftPkg.ApkPkg,
			PURL:    "pkg:apk/alpine/libvncserver@0.9.9?arch=x86_64&distro=alpine-3.12.0",
			CPEs:    []cpe.CPE{cpe.Must(libvncCPE, cpe.DeclaredSource)},
			Metadata: syftPkg.ApkDBEntry{
				Package:      "libvncserver",
				Version:      "0.9.9",
				Architecture: "x86_64",
			},
		},
		{
			Name:     "example-java-app-maven",
			Version:  "0.1.0",
			Type:     syftPkg.JavaPkg,
			Language: syftPkg.Java,
			PURL:     "pkg:maven/org.anchore/example-java-app-maven@0.1.0",
		},
	}
	for i := range pkgs {
		pkgs[i].SetID()
	}

	return sbom.SBOM{
		Artifacts: sbom.Artifacts{
			Packages: syftPkg.NewCollection(pkgs...),
		},
		Descriptor: sbom.Descriptor{
			Name:    "syft",
			Version: "v0.0.0-engage-fixture",
		},
		Source: source.Description{
			Name: "engage-spdx-fixture",
			Metadata: source.DirectoryMetadata{
				Path: "/engage",
				Base: "/engage",
			},
		},
	}
}

func encode(t testing.TB, document sbom.SBOM, version, formatID string) []byte {
	t.Helper()

	var (
		encoder sbom.FormatEncoder
		err     error
	)
	switch formatID {
	case FormatJSON:
		cfg := spdxjson.DefaultEncoderConfig()
		cfg.Version = version
		cfg.Pretty = true
		encoder, err = spdxjson.NewFormatEncoderWithConfig(cfg)
	case FormatTagValue:
		cfg := spdxtagvalue.DefaultEncoderConfig()
		cfg.Version = version
		encoder, err = spdxtagvalue.NewFormatEncoderWithConfig(cfg)
	default:
		t.Fatalf("unknown SPDX format %q", formatID)
	}
	require.NoError(t, err)

	var buf bytes.Buffer
	require.NoError(t, encoder.Encode(&buf, document))
	return buf.Bytes()
}

func arrayContext(t testing.TB, doc []byte) []byte {
	t.Helper()

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(doc, &raw))

	var ctx string
	require.NoError(t, json.Unmarshal(raw["@context"], &ctx))

	listed, err := json.Marshal([]string{ctx})
	require.NoError(t, err)
	raw["@context"] = listed

	out, err := json.Marshal(raw)
	require.NoError(t, err)
	return out
}
