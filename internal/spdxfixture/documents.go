package spdxfixture

// handwrittenJSON22 is a third-party SPDX 2.2 JSON document, not produced by
// Syft's encoder. It carries a PyPI package, an Alpine package (purl distro
// qualifier plus CPE), and a Maven package.
const handwrittenJSON22 = `{
  "spdxVersion": "SPDX-2.2",
  "dataLicense": "CC0-1.0",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "engage-spdx-2.2",
  "documentNamespace": "https://example.com/engage/spdx-2.2",
  "creationInfo": {
    "creators": ["Tool: engage-grype-test"],
    "created": "2026-01-01T00:00:00Z"
  },
  "packages": [
    {
      "name": "pygments",
      "SPDXID": "SPDXRef-pygments",
      "versionInfo": "2.6.1",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:pypi/pygments@2.6.1"
        }
      ]
    },
    {
      "name": "libvncserver",
      "SPDXID": "SPDXRef-libvncserver",
      "versionInfo": "0.9.9",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:apk/alpine/libvncserver@0.9.9?arch=x86_64&distro=alpine-3.12.0"
        },
        {
          "referenceCategory": "SECURITY",
          "referenceType": "cpe23Type",
          "referenceLocator": "cpe:2.3:a:libvncserver:libvncserver:0.9.9:*:*:*:*:*:*:*"
        }
      ]
    },
    {
      "name": "example-java-app-maven",
      "SPDXID": "SPDXRef-example-java-app-maven",
      "versionInfo": "0.1.0",
      "downloadLocation": "NOASSERTION",
      "filesAnalyzed": false,
      "licenseConcluded": "NOASSERTION",
      "licenseDeclared": "NOASSERTION",
      "copyrightText": "NOASSERTION",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE_MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:maven/org.anchore/example-java-app-maven@0.1.0"
        }
      ]
    }
  ]
}
`

// handwrittenTagValue22 is the tag-value form of handwrittenJSON22.
const handwrittenTagValue22 = `SPDXVersion: SPDX-2.2
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: engage-spdx-2.2
DocumentNamespace: https://example.com/engage/spdx-2.2
Creator: Tool: engage-grype-test
Created: 2026-01-01T00:00:00Z

PackageName: pygments
SPDXID: SPDXRef-pygments
PackageVersion: 2.6.1
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:pypi/pygments@2.6.1

PackageName: libvncserver
SPDXID: SPDXRef-libvncserver
PackageVersion: 0.9.9
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:apk/alpine/libvncserver@0.9.9?arch=x86_64&distro=alpine-3.12.0
ExternalRef: SECURITY cpe23Type cpe:2.3:a:libvncserver:libvncserver:0.9.9:*:*:*:*:*:*:*

PackageName: example-java-app-maven
SPDXID: SPDXRef-example-java-app-maven
PackageVersion: 0.1.0
PackageDownloadLocation: NOASSERTION
FilesAnalyzed: false
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION
ExternalRef: PACKAGE-MANAGER purl pkg:maven/org.anchore/example-java-app-maven@0.1.0
`
