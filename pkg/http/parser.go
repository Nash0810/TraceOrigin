package http

import (
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// HTTPEvent represents a captured HTTP request
type HTTPEvent struct {
	PID          uint32 `json:"pid"`
	CgroupID     uint64 `json:"cgroup_id"`
	Comm         string `json:"comm"`
	URL          string `json:"url"`
	Host         string `json:"host"`
	TimestampNs  uint64 `json:"timestamp_ns"`
	Method       string `json:"method"`
	FullURL      string `json:"full_url"`
	DownloadURL  string `json:"download_url"`
	PackageName  string `json:"package_name"`
	Version      string `json:"version"`
}

// URLParser extracts package information from HTTP URLs
type URLParser struct {
	// Regex patterns for common package URLs
	pypiPattern   *regexp.Regexp
	npmPattern    *regexp.Regexp
	gemPattern    *regexp.Regexp
	mavenPattern  *regexp.Regexp
	cargoPattern  *regexp.Regexp
	nugetPattern  *regexp.Regexp
}

// NewURLParser creates a new HTTP URL parser
func NewURLParser() *URLParser {
	return &URLParser{
		// PyPI URLs: https://files.pythonhosted.org/packages/.../package-version.tar.gz
		pypiPattern: regexp.MustCompile(`/packages/.*?/([a-zA-Z0-9\-_.]+)-([0-9]+\.[0-9.]*[a-zA-Z0-9]*)`),
		
		// npm URLs: https://registry.npmjs.org/package/version/
		npmPattern: regexp.MustCompile(`registry\.npmjs\.org/([a-z0-9\-@/]+)/([0-9.]+)`),
		
		// RubyGems URLs: https://rubygems.org/gems/gem-name/versions/version.json
		gemPattern: regexp.MustCompile(`rubygems\.org/.*?/([a-z0-9\-_]+)/versions/([0-9.]+)`),
		
		// Maven URLs: https://repo1.maven.org/maven2/group/artifact/version/artifact-version.jar
		mavenPattern: regexp.MustCompile(`maven2/(.+?)/([a-zA-Z0-9\-_]+)/([0-9.]+[a-zA-Z0-9.\-]*)/\2-\3`),
		
		// Cargo URLs: https://crates.io/api/v1/crates/package/version/download
		cargoPattern: regexp.MustCompile(`crates\.io/api/v1/crates/([a-z0-9\-_]+)/([0-9.]+)`),
		
		// NuGet URLs: https://api.nuget.org/v3/flatcontainer/package/version/package.version.nupkg
		nugetPattern: regexp.MustCompile(`flatcontainer/([a-zA-Z0-9\-_.]+)/([0-9.]+)`),
	}
}

// ParseURLEvent processes an HTTP event and extracts package information
func (p *URLParser) ParseURLEvent(event *HTTPEvent) error {
	// Build full URL
	if event.Host != "" && event.URL != "" {
		if !strings.HasPrefix(event.URL, "/") {
			event.FullURL = "http://" + event.Host + "/" + event.URL
		} else {
			event.FullURL = "http://" + event.Host + event.URL
		}
	} else {
		event.FullURL = event.URL
	}

	// Try to parse as standard URL
	parsedURL, err := url.Parse(event.FullURL)
	if err == nil {
		event.DownloadURL = parsedURL.String()
	} else {
		event.DownloadURL = event.FullURL
	}

	// Extract package info based on domain/pattern
	p.extractPackageInfo(event)

	return nil
}

// extractPackageInfo determines package manager and extracts package name/version
func (p *URLParser) extractPackageInfo(event *HTTPEvent) {
	fullURL := event.FullURL
	
	// Try PyPI
	if strings.Contains(fullURL, "pythonhosted.org") || strings.Contains(fullURL, "pypi.org") {
		if matches := p.pypiPattern.FindStringSubmatch(fullURL); matches != nil {
			event.PackageName = matches[1]
			if len(matches) > 2 {
				event.Version = matches[2]
			}
		}
		return
	}

	// Try npm
	if strings.Contains(fullURL, "registry.npmjs.org") {
		if matches := p.npmPattern.FindStringSubmatch(fullURL); matches != nil {
			event.PackageName = matches[1]
			if len(matches) > 2 {
				event.Version = matches[2]
			}
		}
		return
	}

	// Try RubyGems
	if strings.Contains(fullURL, "rubygems.org") {
		if matches := p.gemPattern.FindStringSubmatch(fullURL); matches != nil {
			event.PackageName = matches[1]
			if len(matches) > 2 {
				event.Version = matches[2]
			}
		}
		return
	}

	// Try Maven
	if strings.Contains(fullURL, "maven") {
		if matches := p.mavenPattern.FindStringSubmatch(fullURL); matches != nil {
			event.PackageName = matches[2]
			if len(matches) > 3 {
				event.Version = matches[3]
			}
		}
		return
	}

	// Try Cargo
	if strings.Contains(fullURL, "crates.io") {
		if matches := p.cargoPattern.FindStringSubmatch(fullURL); matches != nil {
			event.PackageName = matches[1]
			if len(matches) > 2 {
				event.Version = matches[2]
			}
		}
		return
	}

	// Try NuGet
	if strings.Contains(fullURL, "nuget.org") {
		if matches := p.nugetPattern.FindStringSubmatch(fullURL); matches != nil {
			event.PackageName = matches[1]
			if len(matches) > 2 {
				event.Version = matches[2]
			}
		}
		return
	}

	// Fallback: try to extract from filename
	p.extractFromFilename(event)
}

// extractFromFilename attempts to extract package info from URL filename
func (p *URLParser) extractFromFilename(event *HTTPEvent) {
	parsedURL, err := url.Parse(event.FullURL)
	if err != nil {
		return
	}

	path := parsedURL.Path
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return
	}

	filename := parts[len(parts)-1]

	// Common patterns: name-version.ext
	re := regexp.MustCompile(`^([a-zA-Z0-9\-_.]+)-([0-9]+\.[0-9.]*[a-zA-Z0-9.\-]*)`)
	if matches := re.FindStringSubmatch(filename); matches != nil {
		event.PackageName = matches[1]
		if len(matches) > 2 {
			event.Version = matches[2]
		}
	}
}

// MarshalJSON implements json.Marshaler for HTTPEvent
func (e *HTTPEvent) MarshalJSON() ([]byte, error) {
	type Alias HTTPEvent
	return json.Marshal(&struct {
		*Alias
	}{
		Alias: (*Alias)(e),
	})
}
