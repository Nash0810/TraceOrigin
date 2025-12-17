package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Nash0810/TraceOrigin/pkg/correlator"
)

// SPDXBOM represents an SPDX Software Bill of Materials
type SPDXBOM struct {
	SPDXVersion       string           `json:"spdxVersion"`
	DataLicense       string           `json:"dataLicense"`
	SBOMID            string           `json:"SBOMID"`
	Name              string           `json:"name"`
	DocumentNamespace string           `json:"documentNamespace"`
	CreationInfo      CreationInfo     `json:"creationInfo"`
	Packages          []SPDXPackage    `json:"packages"`
	DocumentDescribes []string         `json:"documentDescribes"`
}

// CreationInfo contains creation metadata
type CreationInfo struct {
	Created   time.Time `json:"created"`
	Creators  []string  `json:"creators"`
	LicenseListVersion string `json:"licenseListVersion"`
}

// SPDXPackage represents a package in SPDX format
type SPDXPackage struct {
	SPDXID              string            `json:"SPDXID"`
	Name                string            `json:"name"`
	VersionInfo         string            `json:"versionInfo"`
	PackageDownloadLocation string         `json:"downloadLocation"`
	FilesAnalyzed       bool              `json:"filesAnalyzed"`
	PackageVerificationCode interface{}  `json:"packageVerificationCode,omitempty"`
	ExternalRefs        []SPDXExternalRef `json:"externalRefs,omitempty"`
	Checksums           []SPDXChecksum    `json:"checksums,omitempty"`
}

// SPDXExternalRef represents an external reference in SPDX format
type SPDXExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

// SPDXChecksum represents a checksum in SPDX format
type SPDXChecksum struct {
	Algorithm string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// SPDXGenerator generates SPDX format SBOMs
type SPDXGenerator struct {
	chains []correlator.DependencyChain
}

// NewSPDXGenerator creates a new SPDX generator
func NewSPDXGenerator(chains []correlator.DependencyChain) *SPDXGenerator {
	return &SPDXGenerator{
		chains: chains,
	}
}

// GenerateSPDX generates an SPDX SBOM
func (s *SPDXGenerator) GenerateSPDX() *SPDXBOM {
	now := time.Now().UTC()
	sbom := &SPDXBOM{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SBOMID:            "SPDXRef-SBOM",
		Name:              "TraceOrigin Supply Chain SBOM",
		DocumentNamespace: fmt.Sprintf("https://traceorigin/sbom/%s", now.Format("20060102150405")),
		CreationInfo: CreationInfo{
			Created:            now,
			Creators:           []string{"Tool: supply-tracer-1.0.0"},
			LicenseListVersion: "3.21",
		},
		Packages: []SPDXPackage{},
		DocumentDescribes: []string{},
	}

	// Convert dependency chains to packages
	for i, chain := range s.chains {
		pkg := s.chainToPackage(chain, i)
		sbom.Packages = append(sbom.Packages, pkg)
		sbom.DocumentDescribes = append(sbom.DocumentDescribes, fmt.Sprintf("SPDXRef-Package-%d", i))
	}

	return sbom
}

// chainToPackage converts a DependencyChain to an SPDX Package
func (s *SPDXGenerator) chainToPackage(chain correlator.DependencyChain, index int) SPDXPackage {
	downloadLocation := "NOASSERTION"
	if chain.DownloadURL != "" {
		downloadLocation = chain.DownloadURL
	}

	pkg := SPDXPackage{
		SPDXID:              fmt.Sprintf("SPDXRef-Package-%d", index),
		Name:                chain.PackageName,
		VersionInfo:         chain.ActualVersion,
		PackageDownloadLocation: downloadLocation,
		FilesAnalyzed:       false,
	}

	// Add checksum if available
	if chain.Checksum != "" {
		pkg.Checksums = []SPDXChecksum{
			{
				Algorithm:     "SHA256",
				ChecksumValue: chain.Checksum,
			},
		}
	}

	// Add external references
	refs := []SPDXExternalRef{}

	// Package manager reference
	refs = append(refs, SPDXExternalRef{
		ReferenceCategory: "PACKAGE-MANAGER",
		ReferenceType:     "purl",
		ReferenceLocator:  s.generatePURL(chain),
	})

	// Version verification reference
	if chain.DeclaredVersion != "" {
		refs = append(refs, SPDXExternalRef{
			ReferenceCategory: "OTHER",
			ReferenceType:     "declared-version",
			ReferenceLocator:  chain.DeclaredVersion,
		})
	}

	// Source IP reference if available
	if chain.DownloadIP != "" {
		refs = append(refs, SPDXExternalRef{
			ReferenceCategory: "OTHER",
			ReferenceType:     "source-ip",
			ReferenceLocator:  chain.DownloadIP,
		})
	}

	pkg.ExternalRefs = refs

	return pkg
}

// generatePURL generates a Package URL (PURL) for the package
func (s *SPDXGenerator) generatePURL(chain correlator.DependencyChain) string {
	// PURL format: pkg:manager/name@version
	switch chain.PackageManager {
	case "pip", "python":
		return fmt.Sprintf("pkg:pypi/%s@%s", chain.PackageName, chain.ActualVersion)
	case "npm", "node":
		return fmt.Sprintf("pkg:npm/%s@%s", chain.PackageName, chain.ActualVersion)
	case "gem", "ruby":
		return fmt.Sprintf("pkg:gem/%s@%s", chain.PackageName, chain.ActualVersion)
	case "go":
		return fmt.Sprintf("pkg:golang/%s@%s", chain.PackageName, chain.ActualVersion)
	case "cargo", "rust":
		return fmt.Sprintf("pkg:cargo/%s@%s", chain.PackageName, chain.ActualVersion)
	case "apt", "dpkg", "deb":
		return fmt.Sprintf("pkg:deb/debian/%s@%s", chain.PackageName, chain.ActualVersion)
	case "maven":
		return fmt.Sprintf("pkg:maven/%s@%s", chain.PackageName, chain.ActualVersion)
	default:
		return fmt.Sprintf("pkg:generic/%s@%s", chain.PackageName, chain.ActualVersion)
	}
}

// WriteJSON writes the SBOM to a JSON file
func (s *SPDXGenerator) WriteJSON(path string) error {
	sbom := s.GenerateSPDX()

	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// WriteJSONString returns the SBOM as a JSON string
func (s *SPDXGenerator) WriteJSONString() (string, error) {
	sbom := s.GenerateSPDX()

	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}
