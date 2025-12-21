package correlator

import (
	"regexp"
	"strings"
	"time"

	"github.com/Nash0810/TraceOrigin/pkg/container"
)

// DependencyChain represents a complete dependency download chain
type DependencyChain struct {
	PackageName      string
	DeclaredVersion  string      // From manifest
	ActualVersion    string      // From observed download
	DownloadURL      string
	DownloadIP       string
	DownloadTime     time.Time
	FilesWritten     []string
	Checksum         string
	Verified         bool
	PackageManager   string
	LogEntry         string      // Original log line
}

// ProcessContext tracks a package manager process
type ProcessContext struct {
	PID            uint32
	Comm           string
	StartTime      time.Time
	PackageManager string
	CgroupID       uint64
	ContainerID    string // Resolved container ID/name
}

// NetworkEvent represents a network connection
type NetworkEvent struct {
	PID       uint32
	Comm      string
	SrcAddr   string
	DstAddr   string
	DstPort   uint16
	Timestamp uint64
	IsStart   bool  // true for connect, false for close
}

// FileEvent represents a file creation
type FileEvent struct {
	PID       uint32
	Comm      string
	Path      string
	Timestamp uint64
}

// LogEvent represents captured stdout/stderr
type LogEvent struct {
	PID       uint32
	Comm      string
	FD        uint32
	LogData   string
	Timestamp uint64
}

// HTTPEvent represents captured HTTP request
type HTTPEvent struct {
	PID       uint32
	Comm      string
	URL       string
	Host      string
	Method    uint32
	Timestamp uint64
}

// CorrelationEngine links network events with file events and log output
type CorrelationEngine struct {
	processMap       map[uint32]*ProcessContext
	networkEvents    map[uint32][]*NetworkEvent
	fileEvents       map[uint32][]*FileEvent
	logEvents        map[uint32][]*LogEvent
	httpEvents       map[uint32][]*HTTPEvent
	dependencyChains []DependencyChain

	// Per-PID log line buffers for reassembly
	logBuffers map[uint32]string

	// Container resolver for translating cgroup IDs to container names
	containerResolver *container.ContainerResolver

	// Regex patterns for package extraction
	pythonRegex map[string]*regexp.Regexp
	npmRegex    map[string]*regexp.Regexp
	aptRegex    map[string]*regexp.Regexp
	goRegex     map[string]*regexp.Regexp
	rubyRegex   map[string]*regexp.Regexp
}

// NewCorrelationEngine creates a new correlation engine
func NewCorrelationEngine() *CorrelationEngine {
	engine := &CorrelationEngine{
		processMap:        make(map[uint32]*ProcessContext),
		networkEvents:     make(map[uint32][]*NetworkEvent),
		fileEvents:        make(map[uint32][]*FileEvent),
		logEvents:         make(map[uint32][]*LogEvent),
		httpEvents:        make(map[uint32][]*HTTPEvent),
		dependencyChains:  []DependencyChain{},
		logBuffers:        make(map[uint32]string),
		containerResolver: container.NewContainerResolver(),
		pythonRegex:       make(map[string]*regexp.Regexp),
		npmRegex:          make(map[string]*regexp.Regexp),
		aptRegex:          make(map[string]*regexp.Regexp),
		goRegex:           make(map[string]*regexp.Regexp),
		rubyRegex:         make(map[string]*regexp.Regexp),
	}

	// Compile regex patterns for log parsing
	// Python: "Downloading package_name-1.2.3-py3-none-any.whl"
	engine.pythonRegex["download"] = regexp.MustCompile(
		`Downloading\s+(.+?)-([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

	// Python: "Successfully installed package==1.2.3"
	engine.pythonRegex["install"] = regexp.MustCompile(
		`Successfully installed\s+(.+?)==([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

	// NPM: "added 123 packages"
	engine.npmRegex["added"] = regexp.MustCompile(
		`added\s+(\d+)\s+packages`)

	// NPM: "added package@version" or "npm notice package@version"
	engine.npmRegex["package"] = regexp.MustCompile(
		`(?:added|installed)\s+([a-z0-9\-@/._]+)@([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

	// APT: "Setting up package (1.2.3-ubuntu1)"
	engine.aptRegex["setup"] = regexp.MustCompile(
		`Setting up\s+([^\s:]+)\s+\(([^)]+)\)`)

	// APT: "Unpacking package (1.2.3)"
	engine.aptRegex["unpack"] = regexp.MustCompile(
		`Unpacking\s+([^\s:]+)\s+\(([^)]+)\)`)

	// Go: "go: added github.com/package-name v1.2.3"
	engine.goRegex["added"] = regexp.MustCompile(
		`go:\s+added\s+([a-zA-Z0-9\-./]+)\s+v([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

	// Ruby: "Successfully installed gem-name-1.2.3"
	engine.rubyRegex["installed"] = regexp.MustCompile(
		`Successfully installed\s+([a-zA-Z0-9\-_]+)-([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

	// Ruby: "Installing gem-name-1.2.3"
	engine.rubyRegex["installing"] = regexp.MustCompile(
		`Installing\s+([a-zA-Z0-9\-_]+)-([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)


	return engine
}

// AddProcessEvent records process execution
func (e *CorrelationEngine) AddProcessEvent(pid, ppid uint32, cgroup uint64, comm, argv string) {
	ctx := &ProcessContext{
		PID:            pid,
		Comm:           comm,
		StartTime:      time.Now(),
		PackageManager: comm,
		CgroupID:       cgroup,
	}
	// Resolve container ID from cgroup ID
	ctx.ContainerID = e.containerResolver.ResolveCgroupID(cgroup)

	e.processMap[pid] = ctx
}

// AddNetworkEvent records network connection
func (e *CorrelationEngine) AddNetworkEvent(pid uint32, event *NetworkEvent) {
	e.networkEvents[pid] = append(e.networkEvents[pid], event)
}

// AddFileEvent records file creation
func (e *CorrelationEngine) AddFileEvent(pid uint32, event *FileEvent) {
	e.fileEvents[pid] = append(e.fileEvents[pid], event)
}

// AddHTTPEvent records HTTP request - captures download URLs
func (e *CorrelationEngine) AddHTTPEvent(pid uint32, event *HTTPEvent) {
	e.httpEvents[pid] = append(e.httpEvents[pid], event)

	// Extract package info from HTTP URL
	ctx := e.processMap[pid]
	if ctx == nil {
		return
	}

	// Parse URL to extract package name and version
	chain := e.parseHTTPURL(event.URL, event.Host, ctx, event.Timestamp)
	if chain != nil {
		e.dependencyChains = append(e.dependencyChains, *chain)
	}
}

// parseHTTPURL extracts package information from HTTP URLs
func (e *CorrelationEngine) parseHTTPURL(url, host string, ctx *ProcessContext, timestamp uint64) *DependencyChain {
	// PyPI pattern: package-1.2.3.tar.gz
	if strings.Contains(host, "pythonhosted") || strings.Contains(url, "python") {
		re := regexp.MustCompile(`([a-zA-Z0-9\-_]+)-([0-9]+\.[0-9.]*[a-zA-Z0-9.\-]*)`)
		if matches := re.FindStringSubmatch(url); matches != nil {
			return &DependencyChain{
				PackageName:    matches[1],
				ActualVersion:  matches[2],
				DownloadURL:    url,
				PackageManager: "pip",
				DownloadTime:   time.Now(),
				Verified:       true,
			}
		}
	}

	// npm pattern: registry.npmjs.org/package/version
	if strings.Contains(url, "npmjs") {
		re := regexp.MustCompile(`/([a-z0-9\-@/]+)/([0-9.]+)`)
		if matches := re.FindStringSubmatch(url); matches != nil {
			return &DependencyChain{
				PackageName:    matches[1],
				ActualVersion:  matches[2],
				DownloadURL:    url,
				PackageManager: "npm",
				DownloadTime:   time.Now(),
				Verified:       true,
			}
		}
	}

	// RubyGems pattern: rubygems.org/gem-version.gem
	if strings.Contains(url, "rubygems") {
		re := regexp.MustCompile(`([a-z0-9\-_]+)-([0-9.]+)\.gem`)
		if matches := re.FindStringSubmatch(url); matches != nil {
			return &DependencyChain{
				PackageName:    matches[1],
				ActualVersion:  matches[2],
				DownloadURL:    url,
				PackageManager: "gem",
				DownloadTime:   time.Now(),
				Verified:       true,
			}
		}
	}

	return nil
}

// AddLogEvent records stdout/stderr capture - this is where log-based correlation happens
func (e *CorrelationEngine) AddLogEvent(pid uint32, event *LogEvent) {
	e.logEvents[pid] = append(e.logEvents[pid], event)

	// Append to per-PID buffer (handle split lines)
	e.logBuffers[pid] += event.LogData

	// Check if we have a complete line
	if strings.Contains(e.logBuffers[pid], "\n") {
		lines := strings.Split(e.logBuffers[pid], "\n")

		// Process complete lines
		for i := 0; i < len(lines)-1; i++ {
			line := strings.TrimSpace(lines[i])
			if line != "" {
				e.processLogLine(pid, line, event.Timestamp)
			}
		}

		// Keep incomplete line in buffer
		e.logBuffers[pid] = lines[len(lines)-1]
	} else {
		// Also process log data directly as a potential complete log line (for synthetic events)
		line := strings.TrimSpace(event.LogData)
		if line != "" {
			e.processLogLine(pid, line, event.Timestamp)
		}
	}
}

// processLogLine extracts package information from a log line
func (e *CorrelationEngine) processLogLine(pid uint32, line string, timestamp uint64) {
	ctx := e.processMap[pid]
	if ctx == nil {
		return
	}

	var chain *DependencyChain

	// Match based on package manager
	switch {
	case strings.Contains(ctx.Comm, "pip"):
		chain = e.parsePythonLog(line, ctx, timestamp)
	case strings.Contains(ctx.Comm, "npm") || strings.Contains(ctx.Comm, "yarn"):
		chain = e.parseNpmLog(line, ctx, timestamp)
	case strings.Contains(ctx.Comm, "apt"):
		chain = e.parseAptLog(line, ctx, timestamp)
	case strings.Contains(ctx.Comm, "go"):
		chain = e.parseGoLog(line, ctx, timestamp)
	case strings.Contains(ctx.Comm, "bundle"):
		chain = e.parseRubyLog(line, ctx, timestamp)
	}

	if chain != nil {
		e.dependencyChains = append(e.dependencyChains, *chain)
	}
}

// parsePythonLog extracts package info from pip output
func (e *CorrelationEngine) parsePythonLog(line string, ctx *ProcessContext, timestamp uint64) *DependencyChain {
	// Try to match download pattern
	matches := e.pythonRegex["download"].FindStringSubmatch(line)
	if len(matches) >= 3 {
		chain := &DependencyChain{
			PackageName:    matches[1],
			ActualVersion:  matches[2],
			PackageManager: "pip",
			DownloadTime:   time.Unix(0, int64(timestamp)),
			LogEntry:       line,
		}
		// Link with network connection using time window lookup
		chain.DownloadIP = e.findMatchingConnection(ctx.PID, timestamp)
		return chain
	}

	// Try install pattern
	matches = e.pythonRegex["install"].FindStringSubmatch(line)
	if len(matches) >= 3 {
		chain := &DependencyChain{
			PackageName:    matches[1],
			ActualVersion:  matches[2],
			PackageManager: "pip",
			DownloadTime:   time.Unix(0, int64(timestamp)),
			LogEntry:       line,
			Verified:       true,
		}
		// Link with network connection using time window lookup
		chain.DownloadIP = e.findMatchingConnection(ctx.PID, timestamp)
		return chain
	}

	return nil
}

// parseNpmLog extracts package info from npm output
func (e *CorrelationEngine) parseNpmLog(line string, ctx *ProcessContext, timestamp uint64) *DependencyChain {
	matches := e.npmRegex["package"].FindStringSubmatch(line)
	if len(matches) >= 3 {
		chain := &DependencyChain{
			PackageName:    matches[1],
			ActualVersion:  matches[2],
			PackageManager: "npm",
			DownloadTime:   time.Unix(0, int64(timestamp)),
			LogEntry:       line,
		}
		// Link with network connection using time window lookup
		chain.DownloadIP = e.findMatchingConnection(ctx.PID, timestamp)
		return chain
	}

	return nil
}

// parseAptLog extracts package info from apt output
func (e *CorrelationEngine) parseAptLog(line string, ctx *ProcessContext, timestamp uint64) *DependencyChain {
	// Try setup pattern
	matches := e.aptRegex["setup"].FindStringSubmatch(line)
	if len(matches) >= 3 {
		chain := &DependencyChain{
			PackageName:    matches[1],
			ActualVersion:  matches[2],
			PackageManager: "apt",
			DownloadTime:   time.Unix(0, int64(timestamp)),
			LogEntry:       line,
			Verified:       true,
		}
		// Link with network connection using time window lookup
		chain.DownloadIP = e.findMatchingConnection(ctx.PID, timestamp)
		return chain
	}

	// Try unpack pattern
	matches = e.aptRegex["unpack"].FindStringSubmatch(line)
	if len(matches) >= 3 {
		chain := &DependencyChain{
			PackageName:    matches[1],
			ActualVersion:  matches[2],
			PackageManager: "apt",
			DownloadTime:   time.Unix(0, int64(timestamp)),
			LogEntry:       line,
		}
		// Link with network connection using time window lookup
		chain.DownloadIP = e.findMatchingConnection(ctx.PID, timestamp)
		return chain
	}

	return nil
}

// parseGoLog extracts package info from go get output
func (e *CorrelationEngine) parseGoLog(line string, ctx *ProcessContext, timestamp uint64) *DependencyChain {
	// Try added pattern: "go: added github.com/package-name v1.2.3"
	matches := e.goRegex["added"].FindStringSubmatch(line)
	if len(matches) >= 3 {
		chain := &DependencyChain{
			PackageName:    matches[1],
			ActualVersion:  matches[2],
			PackageManager: "go",
			DownloadTime:   time.Unix(0, int64(timestamp)),
			LogEntry:       line,
			Verified:       true,
		}
		// Link with network connection using time window lookup
		chain.DownloadIP = e.findMatchingConnection(ctx.PID, timestamp)
		return chain
	}

	return nil
}

// parseRubyLog extracts package info from bundle install output
func (e *CorrelationEngine) parseRubyLog(line string, ctx *ProcessContext, timestamp uint64) *DependencyChain {
	// Try installed pattern: "Successfully installed gem-name-1.2.3"
	matches := e.rubyRegex["installed"].FindStringSubmatch(line)
	if len(matches) >= 3 {
		chain := &DependencyChain{
			PackageName:    matches[1],
			ActualVersion:  matches[2],
			PackageManager: "ruby",
			DownloadTime:   time.Unix(0, int64(timestamp)),
			LogEntry:       line,
			Verified:       true,
		}
		// Link with network connection using time window lookup
		chain.DownloadIP = e.findMatchingConnection(ctx.PID, timestamp)
		return chain
	}

	// Try installing pattern: "Installing gem-name-1.2.3"
	matches = e.rubyRegex["installing"].FindStringSubmatch(line)
	if len(matches) >= 3 {
		chain := &DependencyChain{
			PackageName:    matches[1],
			ActualVersion:  matches[2],
			PackageManager: "ruby",
			DownloadTime:   time.Unix(0, int64(timestamp)),
			LogEntry:       line,
		}
		// Link with network connection using time window lookup
		chain.DownloadIP = e.findMatchingConnection(ctx.PID, timestamp)
		return chain
	}

	return nil
}

// findMatchingConnection looks up a network connection that was active at a given timestamp
// Uses a 5-second time window to match log events with network connections
func (e *CorrelationEngine) findMatchingConnection(pid uint32, logTime uint64) string {
	events := e.networkEvents[pid]
	if len(events) == 0 {
		return ""
	}

	// Time window: 5 seconds in nanoseconds
	const timeWindowNano = 5_000_000_000

	// Iterate backwards through network events (most recent first)
	for i := len(events) - 1; i >= 0; i-- {
		conn := events[i]

		// Check if log timestamp falls within 5 seconds after connection start
		// This heuristic captures typical scenario where download happens shortly after connect
		if logTime >= conn.Timestamp && logTime <= (conn.Timestamp+timeWindowNano) {
			// Prefer active (non-closed) connections
			if conn.IsStart {
				return conn.DstAddr
			}
		}

		// Also check if connection is still potentially active (started before log)
		// Useful for longer downloads where close event hasn't arrived yet
		if conn.IsStart && logTime >= conn.Timestamp {
			return conn.DstAddr
		}
	}

	return ""
}

// GetDependencyChains returns all detected dependency chains
func (e *CorrelationEngine) GetDependencyChains() []DependencyChain {
	return e.dependencyChains
}

// CorrelateAll performs full correlation of all events
func (e *CorrelationEngine) CorrelateAll() []DependencyChain {
	// Log-based correlation has already been done in AddLogEvent
	// This method can be extended for additional correlation strategies
	return e.dependencyChains
}
// DetectVersionMismatches identifies packages where declared version differs from actual
func (e *CorrelationEngine) DetectVersionMismatches() []DependencyChain {
	var mismatches []DependencyChain

	for _, chain := range e.dependencyChains {
		// Skip if version can't be verified (no declared or actual version)
		if chain.DeclaredVersion == "" || chain.ActualVersion == "" {
			continue
		}

		// Simple string comparison - exact versions must match
		if chain.DeclaredVersion != chain.ActualVersion {
			mismatch := chain
			mismatch.Verified = false
			mismatches = append(mismatches, mismatch)
		}
	}

	return mismatches
}

// VersionConstraintSatisfied checks if actual version satisfies declared constraint
func VersionConstraintSatisfied(constraint, actual string) bool {
	// Simple exact match for MVP
	// Future: implement semantic versioning (SemVer) constraint checking
	return constraint == actual
}

// LinkManifestToObserved matches declared packages with observed downloads
func (e *CorrelationEngine) LinkManifestToObserved(declaredPackages map[string]string) map[string]*DependencyChain {
	result := make(map[string]*DependencyChain)

	for i := range e.dependencyChains {
		chain := &e.dependencyChains[i]
		declaredVersion, exists := declaredPackages[chain.PackageName]
		if exists {
			chain.DeclaredVersion = declaredVersion
			chain.Verified = VersionConstraintSatisfied(declaredVersion, chain.ActualVersion)
			result[chain.PackageName] = chain
		}
	}

	return result
}