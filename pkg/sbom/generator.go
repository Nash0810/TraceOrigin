package sbom

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/Nash0810/TraceOrigin/pkg/correlator"
)

// CycloneDXVersion represents the SBOM version
const CycloneDXVersion = "1.4"

// ComponentType represents the type of component in the BOM
type ComponentType string

const (
	ComponentTypeLibrary    ComponentType = "library"
	ComponentTypeApplication ComponentType = "application"
	ComponentTypeFramework   ComponentType = "framework"
	ComponentTypeDevice      ComponentType = "device"
	ComponentTypeFile        ComponentType = "file"
	ComponentTypeService     ComponentType = "service"
)

// HashAlgorithm represents hash algorithm types
type HashAlgorithm string

const (
	HashAlgoSHA256 HashAlgorithm = "SHA-256"
	HashAlgoSHA1   HashAlgorithm = "SHA-1"
	HashAlgoMD5    HashAlgorithm = "MD5"
)

// SBOM represents a Software Bill of Materials
type SBOM struct {
	BOMVersion int                `json:"bomVersion"`
	SpecVersion string           `json:"specVersion"`
	Version    int                `json:"version"`
	Metadata   *Metadata          `json:"metadata"`
	Components []Component        `json:"components,omitempty"`
	Services   []Service          `json:"services,omitempty"`
}

// Metadata provides metadata about the SBOM
type Metadata struct {
	Timestamp time.Time `json:"timestamp"`
	Tools     []Tool    `json:"tools"`
	Component *Component `json:"component,omitempty"`
}

// Tool represents a tool that created the SBOM
type Tool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// Component represents a software component in the SBOM
type Component struct {
	BOMRef                string              `json:"bom-ref,omitempty"`
	Type                  ComponentType       `json:"type"`
	Name                  string              `json:"name"`
	Version               string              `json:"version,omitempty"`
	PackageURL            string              `json:"purl,omitempty"`
	CPE                   string              `json:"cpe,omitempty"`
	Hashes                []Hash              `json:"hashes,omitempty"`
	ExternalReferences    []ExternalReference `json:"externalReferences,omitempty"`
	Properties            []Property          `json:"properties,omitempty"`
	Description           string              `json:"description,omitempty"`
	LicenseChoice         interface{}         `json:"licenses,omitempty"` // Can be License or []License
}

// Hash represents a hash of a component
type Hash struct {
	Alg   HashAlgorithm `json:"alg"`
	Value string        `json:"value"`
}

// ExternalReference represents an external reference
type ExternalReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

// Property represents a key-value property
type Property struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// License represents a license
type License struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`
}

// Service represents a service in the SBOM
type Service struct {
	BOMRef string    `json:"bom-ref,omitempty"`
	Name   string    `json:"name"`
	URL    string    `json:"url,omitempty"`
	Hashes []Hash    `json:"hashes,omitempty"`
}

// Generator generates SBOMs from dependency chains
type Generator struct {
	chains []correlator.DependencyChain
	source string // "observed", "manifest", "hybrid"
}

// NewGenerator creates a new SBOM generator
func NewGenerator(chains []correlator.DependencyChain) *Generator {
	return &Generator{
		chains: chains,
		source: "observed",
	}
}

// GenerateCycloneDX generates a CycloneDX SBOM
func (g *Generator) GenerateCycloneDX() *SBOM {
	sbom := &SBOM{
		BOMVersion:  1,
		SpecVersion: CycloneDXVersion,
		Version:     1,
		Metadata: &Metadata{
			Timestamp: time.Now().UTC(),
			Tools: []Tool{
				{
					Name:    "supply-tracer",
					Version: "1.0.0",
				},
			},
		},
		Components: []Component{},
	}

	// Convert dependency chains to components
	for i, chain := range g.chains {
		component := g.chainToComponent(chain, i)
		sbom.Components = append(sbom.Components, component)
	}

	return sbom
}

// chainToComponent converts a DependencyChain to a Component
func (g *Generator) chainToComponent(chain correlator.DependencyChain, index int) Component {
	component := Component{
		BOMRef:  fmt.Sprintf("pkg:%d", index),
		Type:    ComponentTypeLibrary,
		Name:    chain.PackageName,
		Version: chain.ActualVersion,
		PackageURL: g.generatePURL(chain),
	}

	// Add hash if available
	if chain.Checksum != "" {
		component.Hashes = []Hash{
			{
				Alg:   HashAlgoSHA256,
				Value: chain.Checksum,
			},
		}
	}

	// Add external reference for download URL
	if chain.DownloadURL != "" {
		component.ExternalReferences = []ExternalReference{
			{
				Type: "distribution",
				URL:  chain.DownloadURL,
			},
		}
	}

	// Add properties
	properties := []Property{
		{
			Name:  "package_manager",
			Value: chain.PackageManager,
		},
		{
			Name:  "download_timestamp",
			Value: chain.DownloadTime.UTC().Format(time.RFC3339),
		},
	}

	// Add source IP if available
	if chain.DownloadIP != "" {
		properties = append(properties, Property{
			Name:  "download_source_ip",
			Value: chain.DownloadIP,
		})
	}

	// Add log entry if available
	if chain.LogEntry != "" {
		properties = append(properties, Property{
			Name:  "log_entry",
			Value: chain.LogEntry,
		})
	}

	// Add version mismatch information
	if chain.DeclaredVersion != "" {
		properties = append(properties, Property{
			Name:  "declared_version",
			Value: chain.DeclaredVersion,
		})

		versionMatch := chain.DeclaredVersion == chain.ActualVersion
		properties = append(properties, Property{
			Name:  "version_verified",
			Value: fmt.Sprintf("%v", versionMatch),
		})

		if !versionMatch {
			component.Description = fmt.Sprintf(
				"Version mismatch detected: declared=%s, actual=%s",
				chain.DeclaredVersion,
				chain.ActualVersion,
			)
		}
	}

	// Add verification status
	properties = append(properties, Property{
		Name:  "verified",
		Value: fmt.Sprintf("%v", chain.Verified),
	})

	component.Properties = properties

	return component
}

// generatePURL generates a Package URL (PURL) for the component
func (g *Generator) generatePURL(chain correlator.DependencyChain) string {
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
func (g *Generator) WriteJSON(path string) error {
	sbom := g.GenerateCycloneDX()

	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

// WriteJSONString returns the SBOM as a JSON string
func (g *Generator) WriteJSONString() (string, error) {
	sbom := g.GenerateCycloneDX()

	data, err := json.MarshalIndent(sbom, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data), nil
}

// GetComponentCount returns the number of components in the SBOM
func (g *Generator) GetComponentCount() int {
	return len(g.chains)
}

// GetVerifiedCount returns the number of verified components
func (g *Generator) GetVerifiedCount() int {
	count := 0
	for _, chain := range g.chains {
		if chain.Verified {
			count++
		}
	}
	return count
}

// GetMismatchCount returns the number of version mismatches
func (g *Generator) GetMismatchCount() int {
	count := 0
	for _, chain := range g.chains {
		if chain.DeclaredVersion != "" && chain.DeclaredVersion != chain.ActualVersion {
			count++
		}
	}
	return count
}

// GenerateSummary generates a summary of the SBOM
func (g *Generator) GenerateSummary() map[string]interface{} {
	return map[string]interface{}{
		"total_components":     g.GetComponentCount(),
		"verified_components":  g.GetVerifiedCount(),
		"version_mismatches":   g.GetMismatchCount(),
		"generation_timestamp": time.Now().UTC().Format(time.RFC3339),
		"source":               g.source,
	}
}
