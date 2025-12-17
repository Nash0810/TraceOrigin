package export

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

// ExportFormat defines the output format
type ExportFormat string

const (
	FormatJSON      ExportFormat = "json"
	FormatCSV       ExportFormat = "csv"
	FormatXML       ExportFormat = "xml"
	FormatYAML      ExportFormat = "yaml"
	FormatMarkdown  ExportFormat = "markdown"
	FormatProtobuf  ExportFormat = "protobuf"
)

// ExportTarget defines where to export
type ExportTarget string

const (
	TargetFile     ExportTarget = "file"
	TargetDatabase ExportTarget = "database"
	TargetAPI      ExportTarget = "api"
	TargetCloud    ExportTarget = "cloud"
)

// ExportConfig contains configuration for export operations
type ExportConfig struct {
	Format              ExportFormat
	Target              ExportTarget
	Filename            string
	Pretty              bool
	Compression         bool
	Encryption          bool
	FilterByDate        *time.Time
	FilterBySeverity    string
	FilterByPackage     string
	IncludeMetadata     bool
	IncludeHistory      bool
	IncludeRecommendations bool
	Batch               bool
	BatchSize           int
	OutputDir           string
	Timestamp           bool
	ChunkSize           int64
}

// ExportResult contains the result of an export operation
type ExportResult struct {
	Success         bool
	Format          ExportFormat
	Target          ExportTarget
	OutputPath      string
	RecordsExported int
	BytesWritten    int64
	Duration        time.Duration
	Error           string
	Metadata        map[string]interface{}
}

// ExportEntry represents a single entry to export
type ExportEntry struct {
	ID                string                 `json:"id"`
	Type              string                 `json:"type"`
	PackageName       string                 `json:"package_name"`
	PackageVersion    string                 `json:"package_version"`
	PackageManager    string                 `json:"package_manager"`
	Severity          string                 `json:"severity"`
	Description       string                 `json:"description"`
	SourceURL         string                 `json:"source_url"`
	DetectedAt        time.Time              `json:"detected_at"`
	Status            string                 `json:"status"`
	Tags              []string               `json:"tags"`
	Metadata          map[string]interface{} `json:"metadata"`
	ReportedBy        string                 `json:"reported_by"`
	AffectedSystems   []string               `json:"affected_systems"`
	Remediation       string                 `json:"remediation"`
	References        []string               `json:"references"`
}

// Exporter manages export operations
type Exporter struct {
	config  ExportConfig
	entries []ExportEntry
	mu      sync.RWMutex
	filters map[string]FilterFunc
}

// FilterFunc is a function that filters entries
type FilterFunc func(ExportEntry) bool

// NewExporter creates a new exporter
func NewExporter(config ExportConfig) *Exporter {
	if config.BatchSize == 0 {
		config.BatchSize = 1000
	}
	if config.ChunkSize == 0 {
		config.ChunkSize = 1024 * 1024 // 1MB
	}

	return &Exporter{
		config:  config,
		entries: make([]ExportEntry, 0),
		filters: make(map[string]FilterFunc),
	}
}

// AddEntry adds an entry to be exported
func (e *Exporter) AddEntry(entry ExportEntry) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if entry.ID == "" {
		entry.ID = fmt.Sprintf("entry-%d-%d", time.Now().UnixNano(), len(e.entries))
	}
	if entry.DetectedAt.IsZero() {
		entry.DetectedAt = time.Now()
	}
	if entry.Status == "" {
		entry.Status = "active"
	}

	e.entries = append(e.entries, entry)
}

// AddEntries adds multiple entries
func (e *Exporter) AddEntries(entries []ExportEntry) {
	for _, entry := range entries {
		e.AddEntry(entry)
	}
}

// AddFilter adds a filter function
func (e *Exporter) AddFilter(name string, filter FilterFunc) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.filters[name] = filter
}

// ApplyFilters applies all registered filters to entries
func (e *Exporter) ApplyFilters() {
	e.mu.Lock()
	defer e.mu.Unlock()

	for _, filter := range e.filters {
		filtered := make([]ExportEntry, 0)
		for _, entry := range e.entries {
			if filter(entry) {
				filtered = append(filtered, entry)
			}
		}
		e.entries = filtered
	}
}

// Export exports entries in the configured format
func (e *Exporter) Export() (ExportResult, error) {
	startTime := time.Now()

	result := ExportResult{
		Format:     e.config.Format,
		Target:     e.config.Target,
		Success:    false,
		Metadata:   make(map[string]interface{}),
	}

	e.mu.RLock()
	entriesCount := len(e.entries)
	e.mu.RUnlock()

	result.RecordsExported = entriesCount

	var output []byte
	var err error

	switch e.config.Format {
	case FormatJSON:
		output, err = e.exportJSON()
	case FormatCSV:
		output, err = e.exportCSV()
	case FormatXML:
		output, err = e.exportXML()
	case FormatYAML:
		output, err = e.exportYAML()
	case FormatMarkdown:
		output, err = e.exportMarkdown()
	default:
		return result, fmt.Errorf("unsupported export format: %v", e.config.Format)
	}

	if err != nil {
		result.Error = err.Error()
		result.Duration = time.Since(startTime)
		return result, err
	}

	result.BytesWritten = int64(len(output))
	result.Success = true
	result.Duration = time.Since(startTime)
	result.OutputPath = e.config.Filename
	result.Metadata["format"] = string(e.config.Format)
	result.Metadata["compression"] = e.config.Compression
	result.Metadata["encryption"] = e.config.Encryption
	result.Metadata["entries_processed"] = entriesCount
	result.Metadata["exported_at"] = time.Now().String()

	return result, nil
}

// exportJSON exports entries as JSON
func (e *Exporter) exportJSON() ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	data := map[string]interface{}{
		"metadata": map[string]interface{}{
			"format":           "json",
			"exported_at":      time.Now().String(),
			"total_entries":    len(e.entries),
			"version":          "1.0",
			"export_config":    e.config,
		},
		"entries": e.entries,
	}

	if e.config.Pretty {
		return json.MarshalIndent(data, "", "  ")
	}
	return json.Marshal(data)
}

// exportCSV exports entries as CSV
func (e *Exporter) exportCSV() ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	buf := new(bytes.Buffer)
	writer := csv.NewWriter(buf)
	defer writer.Flush()

	// Write header
	header := []string{
		"ID", "Type", "PackageName", "PackageVersion", "PackageManager",
		"Severity", "Description", "SourceURL", "DetectedAt", "Status",
		"Tags", "ReportedBy", "Remediation",
	}
	if err := writer.Write(header); err != nil {
		return nil, err
	}

	// Write entries
	for _, entry := range e.entries {
		record := []string{
			entry.ID,
			entry.Type,
			entry.PackageName,
			entry.PackageVersion,
			entry.PackageManager,
			entry.Severity,
			entry.Description,
			entry.SourceURL,
			entry.DetectedAt.Format(time.RFC3339),
			entry.Status,
			fmt.Sprintf("[%s]", bytes.Join([][]byte{}, []byte(","))),
			entry.ReportedBy,
			entry.Remediation,
		}

		// Add tags
		if len(entry.Tags) > 0 {
			tagStr := ""
			for i, tag := range entry.Tags {
				if i > 0 {
					tagStr += ";"
				}
				tagStr += tag
			}
			record[10] = tagStr
		}

		if err := writer.Write(record); err != nil {
			return nil, err
		}
	}

	return buf.Bytes(), nil
}

// exportXML exports entries as XML
func (e *Exporter) exportXML() ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	buf := new(bytes.Buffer)

	buf.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	buf.WriteString(`<export>` + "\n")
	buf.WriteString(fmt.Sprintf(`  <metadata>` + "\n"))
	buf.WriteString(fmt.Sprintf(`    <format>xml</format>` + "\n"))
	buf.WriteString(fmt.Sprintf(`    <exported_at>%s</exported_at>` + "\n", time.Now().Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf(`    <total_entries>%d</total_entries>` + "\n", len(e.entries)))
	buf.WriteString(fmt.Sprintf(`  </metadata>` + "\n"))
	buf.WriteString(`  <entries>` + "\n")

	for _, entry := range e.entries {
		buf.WriteString(`    <entry>` + "\n")
		buf.WriteString(fmt.Sprintf(`      <id>%s</id>` + "\n", escapeXML(entry.ID)))
		buf.WriteString(fmt.Sprintf(`      <type>%s</type>` + "\n", escapeXML(entry.Type)))
		buf.WriteString(fmt.Sprintf(`      <package_name>%s</package_name>` + "\n", escapeXML(entry.PackageName)))
		buf.WriteString(fmt.Sprintf(`      <package_version>%s</package_version>` + "\n", escapeXML(entry.PackageVersion)))
		buf.WriteString(fmt.Sprintf(`      <severity>%s</severity>` + "\n", escapeXML(entry.Severity)))
		buf.WriteString(fmt.Sprintf(`      <detected_at>%s</detected_at>` + "\n", entry.DetectedAt.Format(time.RFC3339)))
		buf.WriteString(fmt.Sprintf(`      <status>%s</status>` + "\n", escapeXML(entry.Status)))
		buf.WriteString(`    </entry>` + "\n")
	}

	buf.WriteString(`  </entries>` + "\n")
	buf.WriteString(`</export>` + "\n")

	return buf.Bytes(), nil
}

// exportYAML exports entries as YAML
func (e *Exporter) exportYAML() ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	buf := new(bytes.Buffer)

	buf.WriteString("metadata:\n")
	buf.WriteString("  format: yaml\n")
	buf.WriteString(fmt.Sprintf("  exported_at: '%s'\n", time.Now().Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("  total_entries: %d\n", len(e.entries)))
	buf.WriteString("entries:\n")

	for _, entry := range e.entries {
		buf.WriteString("  - id: " + entry.ID + "\n")
		buf.WriteString("    type: " + entry.Type + "\n")
		buf.WriteString("    package_name: " + entry.PackageName + "\n")
		buf.WriteString("    package_version: " + entry.PackageVersion + "\n")
		buf.WriteString("    severity: " + entry.Severity + "\n")
		buf.WriteString("    detected_at: '" + entry.DetectedAt.Format(time.RFC3339) + "'\n")
		buf.WriteString("    status: " + entry.Status + "\n")
	}

	return buf.Bytes(), nil
}

// exportMarkdown exports entries as Markdown
func (e *Exporter) exportMarkdown() ([]byte, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	buf := new(bytes.Buffer)

	buf.WriteString("# Export Report\n\n")
	buf.WriteString(fmt.Sprintf("**Exported at:** %s\n\n", time.Now().Format(time.RFC3339)))
	buf.WriteString(fmt.Sprintf("**Total Entries:** %d\n\n", len(e.entries)))

	// Summary by severity
	severityCounts := make(map[string]int)
	for _, entry := range e.entries {
		severityCounts[entry.Severity]++
	}

	if len(severityCounts) > 0 {
		buf.WriteString("## Summary by Severity\n\n")
		for severity, count := range severityCounts {
			buf.WriteString(fmt.Sprintf("- **%s:** %d\n", severity, count))
		}
		buf.WriteString("\n")
	}

	// Entries table
	buf.WriteString("## Entries\n\n")
	buf.WriteString("| ID | Package | Version | Severity | Status | Detected At |\n")
	buf.WriteString("|---|---|---|---|---|---|\n")

	for _, entry := range e.entries {
		buf.WriteString(fmt.Sprintf(
			"| %s | %s | %s | %s | %s | %s |\n",
			entry.ID,
			entry.PackageName,
			entry.PackageVersion,
			entry.Severity,
			entry.Status,
			entry.DetectedAt.Format("2006-01-02"),
		))
	}

	return buf.Bytes(), nil
}

// GetEntryCount returns the number of entries
func (e *Exporter) GetEntryCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return len(e.entries)
}

// GetEntries returns a copy of all entries
func (e *Exporter) GetEntries() []ExportEntry {
	e.mu.RLock()
	defer e.mu.RUnlock()

	entries := make([]ExportEntry, len(e.entries))
	copy(entries, e.entries)
	return entries
}

// FilterBySeverity filters entries by severity level
func (e *Exporter) FilterBySeverity(severity string) {
	e.AddFilter("severity", func(entry ExportEntry) bool {
		return entry.Severity == severity
	})
}

// FilterByPackage filters entries by package name pattern
func (e *Exporter) FilterByPackage(pattern string) error {
	regex, err := regexp.Compile(pattern)
	if err != nil {
		return err
	}

	e.AddFilter("package", func(entry ExportEntry) bool {
		return regex.MatchString(entry.PackageName)
	})
	return nil
}

// FilterByDateRange filters entries within a date range
func (e *Exporter) FilterByDateRange(start, end time.Time) {
	e.AddFilter("date_range", func(entry ExportEntry) bool {
		return entry.DetectedAt.After(start) && entry.DetectedAt.Before(end)
	})
}

// SortByDate sorts entries by detected date
func (e *Exporter) SortByDate(ascending bool) {
	e.mu.Lock()
	defer e.mu.Unlock()

	sort.Slice(e.entries, func(i, j int) bool {
		if ascending {
			return e.entries[i].DetectedAt.Before(e.entries[j].DetectedAt)
		}
		return e.entries[i].DetectedAt.After(e.entries[j].DetectedAt)
	})
}

// SortBySeverity sorts entries by severity level
func (e *Exporter) SortBySeverity() {
	e.mu.Lock()
	defer e.mu.Unlock()

	severityOrder := map[string]int{
		"critical": 0,
		"high":     1,
		"medium":   2,
		"low":      3,
		"info":     4,
	}

	sort.Slice(e.entries, func(i, j int) bool {
		iOrder := severityOrder[e.entries[i].Severity]
		jOrder := severityOrder[e.entries[j].Severity]
		return iOrder < jOrder
	})
}

// GetStatistics returns statistics about the entries
func (e *Exporter) GetStatistics() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_entries"] = len(e.entries)

	// Count by severity
	severityCounts := make(map[string]int)
	packageCounts := make(map[string]int)
	typeCounts := make(map[string]int)
	statusCounts := make(map[string]int)

	for _, entry := range e.entries {
		severityCounts[entry.Severity]++
		packageCounts[entry.PackageManager]++
		typeCounts[entry.Type]++
		statusCounts[entry.Status]++
	}

	stats["by_severity"] = severityCounts
	stats["by_package_manager"] = packageCounts
	stats["by_type"] = typeCounts
	stats["by_status"] = statusCounts

	return stats
}

// ClearEntries clears all entries
func (e *Exporter) ClearEntries() {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.entries = make([]ExportEntry, 0)
}

// escapeXML escapes XML special characters
func escapeXML(s string) string {
	replacer := regexp.MustCompile(`[&<>"]`)
	return replacer.ReplaceAllStringFunc(s, func(match string) string {
		switch match {
		case "&":
			return "&amp;"
		case "<":
			return "&lt;"
		case ">":
			return "&gt;"
		case "\"":
			return "&quot;"
		}
		return match
	})
}

// ValidateExportConfig validates the export configuration
func ValidateExportConfig(config ExportConfig) []string {
	errors := make([]string, 0)

	if config.Format == "" {
		errors = append(errors, "export format is required")
	}

	if config.Target == "" {
		errors = append(errors, "export target is required")
	}

	if config.BatchSize <= 0 {
		errors = append(errors, "batch size must be positive")
	}

	if config.ChunkSize <= 0 {
		errors = append(errors, "chunk size must be positive")
	}

	return errors
}

// BatchExport exports entries in batches
func (e *Exporter) BatchExport(processFunc func([]ExportEntry) error) error {
	e.mu.RLock()
	defer e.mu.RUnlock()

	for i := 0; i < len(e.entries); i += e.config.BatchSize {
		end := i + e.config.BatchSize
		if end > len(e.entries) {
			end = len(e.entries)
		}

		batch := e.entries[i:end]
		if err := processFunc(batch); err != nil {
			return err
		}
	}

	return nil
}
