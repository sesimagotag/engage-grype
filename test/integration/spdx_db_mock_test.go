package integration

import (
	"github.com/anchore/grype/grype/version"
	"github.com/anchore/grype/grype/vulnerability"
	"github.com/anchore/grype/grype/vulnerability/mock"
)

func newSPDXMockDBProvider() vulnerability.Provider {
	return mock.VulnerabilityProvider(
		vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "CVE-2024-0000",
				Namespace: "alpine:distro:alpine:3.12",
			},
			PackageName: "libvncserver",
			Constraint:  version.MustGetConstraint("< 0.9.10", version.UnknownFormat),
		},
		vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "CVE-python-pygments",
				Namespace: "github:language:python",
			},
			PackageName: "pygments",
			Constraint:  version.MustGetConstraint("< 2.6.2", version.PythonFormat),
		},
		vulnerability.Vulnerability{
			Reference: vulnerability.Reference{
				ID:        "CVE-java-example-java-app",
				Namespace: "github:language:java",
			},
			PackageName: "org.anchore:example-java-app-maven",
			Constraint:  version.MustGetConstraint(">= 0.0.1, < 1.2.0", version.UnknownFormat),
		},
	)
}
