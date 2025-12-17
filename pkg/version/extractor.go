package version

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
)

// ExtractedVersion represents version information from a downloaded/installed package
type ExtractedVersion struct {
	PackageName string
	Version     string
	Source      string // "filename", "metadata", "database", "manifest"
	Verified    bool
	Error       string
}

// Extractor handles version extraction for different package managers
type Extractor struct {
	// Regex patterns for version extraction
	pythonWheelPattern *regexp.Regexp
	pythonTarPattern   *regexp.Regexp
	pythonMetaPattern  *regexp.Regexp

	nodePackagePattern *regexp.Regexp

	rubyGemPattern     *regexp.Regexp
	rubyGemfilePattern *regexp.Regexp

	goModPattern *regexp.Regexp

	rustCargoPattern *regexp.Regexp

	aptFilenamePattern *regexp.Regexp
}

// NewExtractor creates a new version extractor
func NewExtractor() *Extractor {
	return &Extractor{
		// Python patterns
		// wheel: flask-2.3.0-py3-none-any.whl
		pythonWheelPattern: regexp.MustCompile(`^([a-zA-Z0-9\-_.]+)-([0-9]+\.[0-9.]*[a-zA-Z0-9.\-]*)`),

		// tar.gz: flask-2.3.0.tar.gz
		pythonTarPattern: regexp.MustCompile(`^([a-zA-Z0-9\-_.]+)-([0-9]+\.[0-9.]*[a-zA-Z0-9.\-]*)\.tar`),

		// METADATA version line: Version: 2.3.0
		pythonMetaPattern: regexp.MustCompile(`^Version:\s*([0-9]+\.[0-9.]*[a-zA-Z0-9.\-]*)`),

		// Node package.json: "version": "1.2.3"
		nodePackagePattern: regexp.MustCompile(`"version"\s*:\s*"([0-9]+\.[0-9.]*[a-zA-Z0-9.\-]*[a-zA-Z0-9]*)"?`),

		// Ruby gem: gem-1.2.3.gem
		rubyGemPattern: regexp.MustCompile(`^([a-z0-9\-_]+)-([0-9]+\.[0-9.]*[a-zA-Z0-9.\-]*)\.gem`),

		// Gemfile.lock: GEM entry version
		rubyGemfilePattern: regexp.MustCompile(`^\s+([a-z0-9\-_]+)\s+\(([0-9]+\.[0-9.]*[a-zA-Z0-9.\-]*)\)`),

		// Go go.mod: require module v1.2.3
		goModPattern: regexp.MustCompile(`require\s+.+?\s+v?([0-9]+\.[0-9.]*[a-zA-Z0-9.\-]*)`),

		// Rust Cargo: name = "0.1.0"
		rustCargoPattern: regexp.MustCompile(`version\s*=\s*"([0-9]+\.[0-9.]*[a-zA-Z0-9.\-]*)"`),

		// APT: package_1.2.3-ubuntu1_amd64.deb
		aptFilenamePattern: regexp.MustCompile(`^([a-z0-9\-]+)_([0-9]+\.[0-9.]*[a-zA-Z0-9~.\-+:]+)`),
	}
}

// ExtractPythonVersion extracts version from Python wheel, tar.gz, or METADATA file
func (e *Extractor) ExtractPythonVersion(pathOrFilename string) *ExtractedVersion {
	result := &ExtractedVersion{Source: "filename"}

	filename := filepath.Base(pathOrFilename)

	// Try wheel pattern: flask-2.3.0-py3-none-any.whl
	if matches := e.pythonWheelPattern.FindStringSubmatch(filename); matches != nil {
		return &ExtractedVersion{
			PackageName: matches[1],
			Version:     matches[2],
			Source:      "filename",
			Verified:    true,
		}
	}

	// Try tar.gz pattern: flask-2.3.0.tar.gz
	if matches := e.pythonTarPattern.FindStringSubmatch(filename); matches != nil {
		return &ExtractedVersion{
			PackageName: matches[1],
			Version:     matches[2],
			Source:      "filename",
			Verified:    true,
		}
	}

	// Try reading METADATA file if it's a directory
	if info, err := os.Stat(pathOrFilename); err == nil && info.IsDir() {
		// Look for dist-info/METADATA
		distInfoDir := filepath.Join(pathOrFilename, "dist-info")
		if entries, err := os.ReadDir(distInfoDir); err == nil {
			for _, entry := range entries {
				if strings.HasSuffix(entry.Name(), ".dist-info") {
					metadataPath := filepath.Join(distInfoDir, entry.Name(), "METADATA")
					if data, err := os.ReadFile(metadataPath); err == nil {
						lines := strings.Split(string(data), "\n")
						for _, line := range lines {
							if matches := e.pythonMetaPattern.FindStringSubmatch(line); matches != nil {
								// Extract name from first line
								return &ExtractedVersion{
									Version:  matches[1],
									Source:   "metadata",
									Verified: true,
								}
							}
						}
					}
				}
			}
		}
	}

	result.Error = "could not extract Python version"
	return result
}

// ExtractNodeVersion extracts version from Node.js package.json
func (e *Extractor) ExtractNodeVersion(packagePath string) *ExtractedVersion {
	// Try reading package.json from path
	packageJsonPath := packagePath
	if info, err := os.Stat(packagePath); err == nil && info.IsDir() {
		packageJsonPath = filepath.Join(packagePath, "package.json")
	}

	data, err := os.ReadFile(packageJsonPath)
	if err != nil {
		return &ExtractedVersion{
			Error:  fmt.Sprintf("could not read package.json: %v", err),
			Source: "manifest",
		}
	}

	// Parse JSON
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return &ExtractedVersion{
			Error:  fmt.Sprintf("could not parse package.json: %v", err),
			Source: "manifest",
		}
	}

	return &ExtractedVersion{
		PackageName: pkg.Name,
		Version:     pkg.Version,
		Source:      "manifest",
		Verified:    true,
	}
}

// ExtractAptVersion extracts version from dpkg database
func (e *Extractor) ExtractAptVersion(packageName string) *ExtractedVersion {
	// Query dpkg database: dpkg-query -W -f='${Version}' package_name
	cmd := exec.Command("dpkg-query", "-W", "-f=${Version}", packageName)
	output, err := cmd.Output()
	if err != nil {
		return &ExtractedVersion{
			PackageName: packageName,
			Error:       fmt.Sprintf("dpkg-query failed: %v", err),
			Source:      "database",
		}
	}

	version := strings.TrimSpace(string(output))
	if version == "" {
		return &ExtractedVersion{
			PackageName: packageName,
			Error:       "package not found in dpkg database",
			Source:      "database",
		}
	}

	return &ExtractedVersion{
		PackageName: packageName,
		Version:     version,
		Source:      "database",
		Verified:    true,
	}
}

// ExtractAptVersionFromFilename extracts version from Debian package filename
func (e *Extractor) ExtractAptVersionFromFilename(filename string) *ExtractedVersion {
	// Pattern: package_1.2.3-ubuntu1_amd64.deb
	if matches := e.aptFilenamePattern.FindStringSubmatch(filename); matches != nil {
		return &ExtractedVersion{
			PackageName: matches[1],
			Version:     matches[2],
			Source:      "filename",
			Verified:    true,
		}
	}

	return &ExtractedVersion{
		Error:  "could not extract APT version from filename",
		Source: "filename",
	}
}

// ExtractRubyVersion extracts version from Ruby gem file or Gemfile.lock
func (e *Extractor) ExtractRubyVersion(pathOrFilename string) *ExtractedVersion {
	filename := filepath.Base(pathOrFilename)

	// Try gem filename pattern: rails-7.0.0.gem
	if matches := e.rubyGemPattern.FindStringSubmatch(filename); matches != nil {
		return &ExtractedVersion{
			PackageName: matches[1],
			Version:     matches[2],
			Source:      "filename",
			Verified:    true,
		}
	}

	// Try reading Gemfile.lock
	if strings.HasSuffix(pathOrFilename, "Gemfile.lock") {
		data, err := os.ReadFile(pathOrFilename)
		if err != nil {
			return &ExtractedVersion{
				Error:  fmt.Sprintf("could not read Gemfile.lock: %v", err),
				Source: "manifest",
			}
		}

		// Parse Gemfile.lock - each gem entry has name (version) format
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			if matches := e.rubyGemfilePattern.FindStringSubmatch(line); matches != nil {
				return &ExtractedVersion{
					PackageName: matches[1],
					Version:     matches[2],
					Source:      "manifest",
					Verified:    true,
				}
			}
		}
	}

	return &ExtractedVersion{
		Error:  "could not extract Ruby version",
		Source: "filename",
	}
}

// ExtractGoVersion extracts version from go.mod file
func (e *Extractor) ExtractGoVersion(goModPath string) *ExtractedVersion {
	// Read go.mod
	data, err := os.ReadFile(goModPath)
	if err != nil {
		return &ExtractedVersion{
			Error:  fmt.Sprintf("could not read go.mod: %v", err),
			Source: "manifest",
		}
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "require") && !strings.HasPrefix(strings.TrimSpace(line), "//") {
			// Handle both "require module v1.2.3" and multi-line require blocks
			if matches := e.goModPattern.FindStringSubmatch(line); matches != nil {
				// Extract module name from line
				parts := strings.Fields(line)
				if len(parts) >= 3 {
					return &ExtractedVersion{
						PackageName: parts[1],
						Version:     matches[1],
						Source:      "manifest",
						Verified:    true,
					}
				}
			}
		}
	}

	return &ExtractedVersion{
		Error:  "could not extract Go version from go.mod",
		Source: "manifest",
	}
}

// ExtractRustVersion extracts version from Cargo.toml file
func (e *Extractor) ExtractRustVersion(cargoTomlPath string) *ExtractedVersion {
	// Read Cargo.toml
	data, err := os.ReadFile(cargoTomlPath)
	if err != nil {
		return &ExtractedVersion{
			Error:  fmt.Sprintf("could not read Cargo.toml: %v", err),
			Source: "manifest",
		}
	}

	lines := strings.Split(string(data), "\n")
	var inDependencies bool

	for _, line := range lines {
		// Check for [dependencies] section
		if strings.TrimSpace(line) == "[dependencies]" {
			inDependencies = true
			continue
		}

		if inDependencies {
			// Parse dependency version: name = "1.2.3"
			if matches := e.rustCargoPattern.FindStringSubmatch(line); matches != nil {
				// Extract name from before the version
				parts := strings.Split(line, "=")
				if len(parts) >= 2 {
					name := strings.TrimSpace(parts[0])
					return &ExtractedVersion{
						PackageName: name,
						Version:     matches[1],
						Source:      "manifest",
						Verified:    true,
					}
				}
			}
		}
	}

	return &ExtractedVersion{
		Error:  "could not extract Rust version from Cargo.toml",
		Source: "manifest",
	}
}

// DetectPackageManager determines which extractor to use based on filename/path
func (e *Extractor) DetectPackageManager(pathOrFilename string) string {
	lower := strings.ToLower(pathOrFilename)

	if strings.Contains(lower, ".whl") || strings.Contains(lower, ".tar.gz") {
		return "python"
	}
	if strings.Contains(lower, "package.json") {
		return "node"
	}
	if strings.Contains(lower, "gemfile") || strings.Contains(lower, ".gem") {
		return "ruby"
	}
	if strings.Contains(lower, "go.mod") {
		return "go"
	}
	if strings.Contains(lower, "cargo.toml") {
		return "rust"
	}
	if strings.Contains(lower, ".deb") || strings.Contains(lower, "dpkg") {
		return "apt"
	}

	return "unknown"
}

// ExtractAny attempts to extract version from any supported package type
func (e *Extractor) ExtractAny(pathOrFilename string) *ExtractedVersion {
	pm := e.DetectPackageManager(pathOrFilename)

	switch pm {
	case "python":
		return e.ExtractPythonVersion(pathOrFilename)
	case "node":
		return e.ExtractNodeVersion(pathOrFilename)
	case "ruby":
		return e.ExtractRubyVersion(pathOrFilename)
	case "go":
		return e.ExtractGoVersion(pathOrFilename)
	case "rust":
		return e.ExtractRustVersion(pathOrFilename)
	case "apt":
		return e.ExtractAptVersionFromFilename(filepath.Base(pathOrFilename))
	default:
		return &ExtractedVersion{
			Error:  fmt.Sprintf("unknown package manager for: %s", pathOrFilename),
			Source: "unknown",
		}
	}
}
