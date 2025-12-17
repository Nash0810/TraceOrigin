package manifest

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Manifest represents a parsed package manager manifest
type Manifest struct {
	Type     string
	Path     string
	Packages []DeclaredPackage
}

// DeclaredPackage represents a package declared in a manifest
type DeclaredPackage struct {
	Name       string
	Version    string
	Constraint string
}

// ParseManifest detects manifest type and parses it
func ParseManifest(path string) (*Manifest, error) {
	// Detect manifest type from filename
	base := filepath.Base(path)

	switch base {
	case "requirements.txt", "Pipfile":
		return parsePythonRequirements(path)
	case "package.json", "package-lock.json":
		return parseNodePackageJson(path)
	case "go.mod":
		return parseGoMod(path)
	case "Gemfile", "Gemfile.lock":
		return parseGemfile(path)
	case "Cargo.toml":
		return parseCargoToml(path)
	default:
		return nil, fmt.Errorf("unsupported manifest type: %s", base)
	}
}

// parsePythonRequirements parses Python requirements.txt or Pipfile
func parsePythonRequirements(path string) (*Manifest, error) {
	manifest := &Manifest{
		Type:     "pip",
		Path:     path,
		Packages: []DeclaredPackage{},
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open requirements.txt: %w", err)
	}
	defer file.Close()

	// Regex: package_name==1.2.3 or package>=1.0 or package[extra]~=1.5
	re := regexp.MustCompile(`^([a-zA-Z0-9\-_.]+)(?:\[[^\]]*\])?(\s*)(==|>=|<=|~=|!=|>|<)?(.*)`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) >= 4 {
			pkg := DeclaredPackage{
				Name:       matches[1],
				Constraint: matches[3],
				Version:    strings.TrimSpace(matches[4]),
			}
			manifest.Packages = append(manifest.Packages, pkg)
		}
	}

	return manifest, scanner.Err()
}

// parseNodePackageJson parses Node.js package.json
func parseNodePackageJson(path string) (*Manifest, error) {
	manifest := &Manifest{
		Type:     "npm",
		Path:     path,
		Packages: []DeclaredPackage{},
	}

	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read package.json: %w", err)
	}

	var pkgJson struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}

	if err := json.Unmarshal(data, &pkgJson); err != nil {
		return nil, fmt.Errorf("failed to parse package.json: %w", err)
	}

	// Parse dependencies
	for name, version := range pkgJson.Dependencies {
		pkg := DeclaredPackage{
			Name:       name,
			Version:    strings.TrimPrefix(version, "^"),
			Constraint: detectNpmConstraint(version),
		}
		manifest.Packages = append(manifest.Packages, pkg)
	}

	// Parse dev dependencies
	for name, version := range pkgJson.DevDependencies {
		pkg := DeclaredPackage{
			Name:       name,
			Version:    strings.TrimPrefix(version, "^"),
			Constraint: detectNpmConstraint(version),
		}
		manifest.Packages = append(manifest.Packages, pkg)
	}

	return manifest, nil
}

// detectNpmConstraint determines the constraint type for npm versions
func detectNpmConstraint(version string) string {
	if strings.HasPrefix(version, "^") {
		return "caret"
	} else if strings.HasPrefix(version, "~") {
		return "tilde"
	} else if strings.HasPrefix(version, ">=") || strings.HasPrefix(version, ">") {
		return "range"
	} else if strings.HasPrefix(version, "=") {
		return "exact"
	}
	return "version"
}

// parseGoMod parses Go go.mod
func parseGoMod(path string) (*Manifest, error) {
	manifest := &Manifest{
		Type:     "go",
		Path:     path,
		Packages: []DeclaredPackage{},
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open go.mod: %w", err)
	}
	defer file.Close()

	// Regex: require module.name v1.2.3 or require (...)
	re := regexp.MustCompile(`require\s+([^\s]+)\s+v?([^\s]+)`)

	scanner := bufio.NewScanner(file)
	inRequire := false

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Handle multi-line require block
		if strings.HasPrefix(line, "require (") {
			inRequire = true
			continue
		}
		if inRequire && line == ")" {
			inRequire = false
			continue
		}

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			pkg := DeclaredPackage{
				Name:    matches[1],
				Version: matches[2],
			}
			manifest.Packages = append(manifest.Packages, pkg)
		}
	}

	return manifest, scanner.Err()
}

// parseGemfile parses Ruby Gemfile
func parseGemfile(path string) (*Manifest, error) {
	manifest := &Manifest{
		Type:     "gem",
		Path:     path,
		Packages: []DeclaredPackage{},
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Gemfile: %w", err)
	}
	defer file.Close()

	// Regex: gem 'rails', '~> 6.1.0' or gem 'puma'
	re := regexp.MustCompile(`gem\s+['"]([^'"]+)['"],?\s*['"]?([^'"]*)['"]?`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) >= 2 {
			pkg := DeclaredPackage{
				Name:    matches[1],
				Version: strings.TrimSpace(strings.TrimPrefix(matches[2], "~> ")),
			}

			if strings.Contains(matches[2], "~>") {
				pkg.Constraint = "pessimistic"
			}

			manifest.Packages = append(manifest.Packages, pkg)
		}
	}

	return manifest, scanner.Err()
}

// parseCargoToml parses Rust Cargo.toml
func parseCargoToml(path string) (*Manifest, error) {
	manifest := &Manifest{
		Type:     "cargo",
		Path:     path,
		Packages: []DeclaredPackage{},
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open Cargo.toml: %w", err)
	}
	defer file.Close()

	// Simple regex for [dependencies] section
	inDependencies := false
	re := regexp.MustCompile(`^([a-z0-9_-]+)\s*=\s*['"]*([^'"]*)['"]*`)

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "[dependencies]" {
			inDependencies = true
			continue
		}

		if strings.HasPrefix(line, "[") {
			inDependencies = false
			continue
		}

		if !inDependencies {
			continue
		}

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		matches := re.FindStringSubmatch(line)
		if len(matches) >= 3 {
			pkg := DeclaredPackage{
				Name:    matches[1],
				Version: matches[2],
			}
			manifest.Packages = append(manifest.Packages, pkg)
		}
	}

	return manifest, scanner.Err()
}

// FindPackage finds a package by name in the manifest
func (m *Manifest) FindPackage(name string) *DeclaredPackage {
	for i, pkg := range m.Packages {
		if pkg.Name == name {
			return &m.Packages[i]
		}
	}
	return nil
}

// GetPackageCount returns the number of packages in the manifest
func (m *Manifest) GetPackageCount() int {
	return len(m.Packages)
}
