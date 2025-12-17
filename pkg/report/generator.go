package report

import (
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Nash0810/TraceOrigin/pkg/anomaly"
	"github.com/Nash0810/TraceOrigin/pkg/reputation"
)

// ReportFormat defines the output format for reports
type ReportFormat string

const (
	FormatJSON ReportFormat = "json"
	FormatHTML ReportFormat = "html"
	FormatCSV  ReportFormat = "csv"
	FormatText ReportFormat = "text"
)

// ReportType defines the type of report to generate
type ReportType string

const (
	TypeSummary        ReportType = "summary"
	TypeVulnerability  ReportType = "vulnerability"
	TypeDependency     ReportType = "dependency"
	TypeReputation     ReportType = "reputation"
	TypeCompliance     ReportType = "compliance"
	TypeThreatAnalysis ReportType = "threat_analysis"
)

// Report represents a generated report
type Report struct {
	ID              string                 `json:"id"`
	Title           string                 `json:"title"`
	ReportType      ReportType             `json:"report_type"`
	Format          ReportFormat           `json:"format"`
	GeneratedAt     time.Time              `json:"generated_at"`
	GeneratedBy     string                 `json:"generated_by"`
	Version         string                 `json:"version"`
	Summary         *ReportSummary         `json:"summary,omitempty"`
	Vulnerabilities []VulnerabilityFinding `json:"vulnerabilities,omitempty"`
	Dependencies    []DependencyEntry      `json:"dependencies,omitempty"`
	Reputation      *ReputationAnalysis    `json:"reputation,omitempty"`
	Statistics      *ReportStatistics      `json:"statistics,omitempty"`
	Recommendations []Recommendation       `json:"recommendations,omitempty"`
	ExecutiveSummary string                `json:"executive_summary,omitempty"`
	Content         string                 `json:"content,omitempty"`
	Metadata        map[string]interface{} `json:"metadata,omitempty"`
}

// ReportSummary provides high-level summary information
type ReportSummary struct {
	TotalPackages       int     `json:"total_packages"`
	VulnerablePackages  int     `json:"vulnerable_packages"`
	RiskScore           float64 `json:"risk_score"`
	ComplianceScore     float64 `json:"compliance_score"`
	AnomaliesDetected   int     `json:"anomalies_detected"`
	CriticalIssues      int     `json:"critical_issues"`
	HighIssues          int     `json:"high_issues"`
	MediumIssues        int     `json:"medium_issues"`
	LowIssues           int     `json:"low_issues"`
	UnknownPackages     int     `json:"unknown_packages"`
	TrustedPackages     int     `json:"trusted_packages"`
	SuspiciousPackages  int     `json:"suspicious_packages"`
	ReportGeneratedTime time.Time `json:"report_generated_time"`
}

// VulnerabilityFinding represents a vulnerability finding in the report
type VulnerabilityFinding struct {
	PackageName    string   `json:"package_name"`
	PackageVersion string   `json:"package_version"`
	Severity       string   `json:"severity"`
	CVE            string   `json:"cve,omitempty"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	AffectedVersions []string `json:"affected_versions"`
	FixedVersion   string   `json:"fixed_version,omitempty"`
	CVSS           float64  `json:"cvss,omitempty"`
	PublishedDate  time.Time `json:"published_date,omitempty"`
	Remediation    string   `json:"remediation,omitempty"`
}

// DependencyEntry represents a dependency in the report
type DependencyEntry struct {
	Name              string                 `json:"name"`
	InstalledVersion  string                 `json:"installed_version"`
	LatestVersion     string                 `json:"latest_version,omitempty"`
	UpdateAvailable   bool                   `json:"update_available"`
	ReputationScore   float64                `json:"reputation_score,omitempty"`
	TrustLevel        string                 `json:"trust_level,omitempty"`
	VulnerabilityCount int                   `json:"vulnerability_count"`
	IsTransitive      bool                   `json:"is_transitive"`
	Depth             int                    `json:"depth,omitempty"`
	License           string                 `json:"license,omitempty"`
	SourceRepository  string                 `json:"source_repository,omitempty"`
}

// ReputationAnalysis provides reputation analysis
type ReputationAnalysis struct {
	AverageReputationScore    float64 `json:"average_reputation_score"`
	TrustedPercentage         float64 `json:"trusted_percentage"`
	SuspiciousPercentage      float64 `json:"suspicious_percentage"`
	MaliciousPercentage       float64 `json:"malicious_percentage"`
	UnknownPercentage         float64 `json:"unknown_percentage"`
	VerifiedMaintainersCount  int     `json:"verified_maintainers_count"`
	UnverifiedMaintainersCount int    `json:"unverified_maintainers_count"`
	OrganizationPackages      int     `json:"organization_packages"`
	IndividualMaintainers     int     `json:"individual_maintainers"`
	AveragePackageAge         float64 `json:"average_package_age_days"`
	OutdatedPackageCount      int     `json:"outdated_package_count"`
}

// ReportStatistics provides statistical information
type ReportStatistics struct {
	TotalDependencies       int     `json:"total_dependencies"`
	DirectDependencies      int     `json:"direct_dependencies"`
	TransitiveDependencies  int     `json:"transitive_dependencies"`
	AverageDepthLevel       float64 `json:"average_depth_level"`
	MaxDepthLevel           int     `json:"max_depth_level"`
	CircularDependencies    int     `json:"circular_dependencies"`
	DuplicateDependencies   int     `json:"duplicate_dependencies"`
	AnomalyDetectionRate    float64 `json:"anomaly_detection_rate"`
	ScanDurationMs          int64   `json:"scan_duration_ms"`
	PackageManagerCount     int     `json:"package_manager_count"`
}

// Recommendation represents a recommendation in the report
type Recommendation struct {
	Priority    string `json:"priority"`      // critical, high, medium, low
	Category    string `json:"category"`      // security, update, performance, etc.
	Title       string `json:"title"`
	Description string `json:"description"`
	Action      string `json:"action"`
	Impact      string `json:"impact"`
	Effort      string `json:"effort"`        // low, medium, high
}

// ReportGenerator manages report generation
type ReportGenerator struct {
	anomalies     []*anomaly.Anomaly
	repDB         *reputation.ReputationDatabase
	dependencies  map[string]*DependencyEntry
	metadata      map[string]interface{}
	templates     map[string]string
	mu            sync.RWMutex
	generatedReports []*Report
}

// NewReportGenerator creates a new report generator
func NewReportGenerator(repDB *reputation.ReputationDatabase) *ReportGenerator {
	return &ReportGenerator{
		anomalies:        make([]*anomaly.Anomaly, 0),
		repDB:            repDB,
		dependencies:     make(map[string]*DependencyEntry),
		metadata:         make(map[string]interface{}),
		templates:        make(map[string]string),
		generatedReports: make([]*Report, 0),
	}
}

// AddAnomaly adds an anomaly to the report
func (rg *ReportGenerator) AddAnomaly(anom *anomaly.Anomaly) {
	if anom == nil {
		return
	}

	rg.mu.Lock()
	defer rg.mu.Unlock()

	rg.anomalies = append(rg.anomalies, anom)
}

// AddDependency adds a dependency to the report
func (rg *ReportGenerator) AddDependency(dep *DependencyEntry) error {
	if dep == nil || dep.Name == "" {
		return fmt.Errorf("dependency cannot be nil or have empty name")
	}

	rg.mu.Lock()
	defer rg.mu.Unlock()

	rg.dependencies[dep.Name] = dep
	return nil
}

// SetMetadata sets metadata for the report
func (rg *ReportGenerator) SetMetadata(key string, value interface{}) {
	rg.mu.Lock()
	defer rg.mu.Unlock()

	rg.metadata[key] = value
}

// GenerateReport generates a report based on collected data
func (rg *ReportGenerator) GenerateReport(reportType ReportType, format ReportFormat) (*Report, error) {
	rg.mu.Lock()
	defer rg.mu.Unlock()

	if len(rg.dependencies) == 0 && len(rg.anomalies) == 0 {
		return nil, fmt.Errorf("no data to generate report")
	}

	report := &Report{
		ID:          generateReportID(),
		Title:       fmt.Sprintf("%s Report", reportType),
		ReportType:  reportType,
		Format:      format,
		GeneratedAt: time.Now(),
		Version:     "1.0",
		Metadata:    rg.metadata,
	}

	// Generate summary
	report.Summary = rg.generateSummary()
	report.Statistics = rg.generateStatistics()

	// Generate type-specific content
	switch reportType {
	case TypeVulnerability:
		report.Vulnerabilities = rg.generateVulnerabilityFindings()
		report.Recommendations = rg.generateSecurityRecommendations()

	case TypeDependency:
		report.Dependencies = rg.generateDependencyReport()
		report.Recommendations = rg.generateDependencyRecommendations()

	case TypeReputation:
		report.Reputation = rg.generateReputationAnalysis()
		report.Recommendations = rg.generateReputationRecommendations()

	case TypeThreatAnalysis:
		report.Vulnerabilities = rg.generateVulnerabilityFindings()
		report.Reputation = rg.generateReputationAnalysis()
		report.Recommendations = rg.generateThreatRecommendations()

	case TypeCompliance:
		report.Summary = rg.generateSummary()
		report.Recommendations = rg.generateComplianceRecommendations()

	default:
		report.Summary = rg.generateSummary()
		report.Dependencies = rg.generateDependencyReport()
	}

	// Generate executive summary
	report.ExecutiveSummary = rg.generateExecutiveSummary(report)

	// Format content
	report.Content = rg.formatReport(report, format)

	rg.generatedReports = append(rg.generatedReports, report)

	return report, nil
}

// generateSummary generates a summary
func (rg *ReportGenerator) generateSummary() *ReportSummary {
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	totalVulnerable := 0
	totalAnomalies := 0

	for _, anom := range rg.anomalies {
		totalAnomalies++
		switch anom.Severity {
		case "critical":
			criticalCount++
		case "high":
			highCount++
		case "medium":
			mediumCount++
		case "low":
			lowCount++
		}
		if anom.ThreatScore > 50 {
			totalVulnerable++
		}
	}

	trustedCount := 0
	suspiciousCount := 0
	unknownCount := 0

	if rg.repDB != nil {
		trustedCount = len(rg.repDB.GetTrustedPackages())
		suspiciousCount = len(rg.repDB.GetBlacklistedPackages())
		unknownCount = len(rg.dependencies) - trustedCount - suspiciousCount
		if unknownCount < 0 {
			unknownCount = 0
		}
	}

	riskScore := calculateRiskScore(criticalCount, highCount, mediumCount, lowCount)
	complianceScore := calculateComplianceScore(trustedCount, len(rg.dependencies))

	return &ReportSummary{
		TotalPackages:      len(rg.dependencies),
		VulnerablePackages: totalVulnerable,
		RiskScore:          riskScore,
		ComplianceScore:    complianceScore,
		AnomaliesDetected:  totalAnomalies,
		CriticalIssues:     criticalCount,
		HighIssues:         highCount,
		MediumIssues:       mediumCount,
		LowIssues:          lowCount,
		UnknownPackages:    unknownCount,
		TrustedPackages:    trustedCount,
		SuspiciousPackages: suspiciousCount,
		ReportGeneratedTime: time.Now(),
	}
}

// generateStatistics generates statistics
func (rg *ReportGenerator) generateStatistics() *ReportStatistics {
	maxDepth := 0
	totalDepth := 0
	directCount := 0
	transitiveCount := 0

	for _, dep := range rg.dependencies {
		if dep.Depth > maxDepth {
			maxDepth = dep.Depth
		}
		totalDepth += dep.Depth

		if dep.IsTransitive {
			transitiveCount++
		} else {
			directCount++
		}
	}

	avgDepth := 0.0
	if len(rg.dependencies) > 0 {
		avgDepth = float64(totalDepth) / float64(len(rg.dependencies))
	}

	anomalyRate := 0.0
	if len(rg.dependencies) > 0 {
		anomalyRate = float64(len(rg.anomalies)) / float64(len(rg.dependencies)) * 100
	}

	return &ReportStatistics{
		TotalDependencies:      len(rg.dependencies),
		DirectDependencies:     directCount,
		TransitiveDependencies: transitiveCount,
		AverageDepthLevel:      avgDepth,
		MaxDepthLevel:          maxDepth,
		AnomalyDetectionRate:   anomalyRate,
	}
}

// generateVulnerabilityFindings generates vulnerability findings
func (rg *ReportGenerator) generateVulnerabilityFindings() []VulnerabilityFinding {
	findings := make([]VulnerabilityFinding, 0)

	for _, anom := range rg.anomalies {
		if anom.Severity == "critical" || anom.Severity == "high" {
			finding := VulnerabilityFinding{
				PackageName: anom.PackageName,
				Severity:    anom.Severity,
				Title:       anom.AnomalyType,
				Description: anom.Description,
				Remediation: anom.Remediation,
				PublishedDate: time.Now(),
			}
			findings = append(findings, finding)
		}
	}

	return findings
}

// generateDependencyReport generates dependency report
func (rg *ReportGenerator) generateDependencyReport() []DependencyEntry {
	entries := make([]DependencyEntry, 0, len(rg.dependencies))

	for _, dep := range rg.dependencies {
		entries = append(entries, *dep)
	}

	return entries
}

// generateReputationAnalysis generates reputation analysis
func (rg *ReportGenerator) generateReputationAnalysis() *ReputationAnalysis {
	if rg.repDB == nil {
		return &ReputationAnalysis{}
	}

	analysis := &ReputationAnalysis{
		AverageReputationScore:    rg.repDB.GetAverageCommunityRating(),
		VerifiedMaintainersCount:  0,
		UnverifiedMaintainersCount: 0,
		OrganizationPackages:      0,
		IndividualMaintainers:     0,
	}

	totalPackages := rg.repDB.GetSize()
	if totalPackages > 0 {
		trustedCount := len(rg.repDB.GetTrustedPackages())
		blacklistedCount := len(rg.repDB.GetBlacklistedPackages())

		analysis.TrustedPercentage = float64(trustedCount) / float64(totalPackages) * 100
		analysis.SuspiciousPercentage = float64(blacklistedCount) / float64(totalPackages) * 100
		analysis.UnknownPercentage = 100 - analysis.TrustedPercentage - analysis.SuspiciousPercentage
	}

	return analysis
}

// generateSecurityRecommendations generates security-focused recommendations
func (rg *ReportGenerator) generateSecurityRecommendations() []Recommendation {
	recommendations := make([]Recommendation, 0)

	criticalCount := 0
	for _, anom := range rg.anomalies {
		if anom.Severity == "critical" {
			criticalCount++
		}
	}

	if criticalCount > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority:    "critical",
			Category:    "security",
			Title:       "Address Critical Vulnerabilities",
			Description: fmt.Sprintf("Found %d critical vulnerabilities that require immediate attention", criticalCount),
			Action:      "Update vulnerable packages to patched versions",
			Impact:      "Eliminates critical security risks",
			Effort:      "low",
		})
	}

	return recommendations
}

// generateDependencyRecommendations generates dependency-focused recommendations
func (rg *ReportGenerator) generateDependencyRecommendations() []Recommendation {
	recommendations := make([]Recommendation, 0)

	outdatedCount := 0
	for _, dep := range rg.dependencies {
		if dep.UpdateAvailable {
			outdatedCount++
		}
	}

	if outdatedCount > 0 {
		recommendations = append(recommendations, Recommendation{
			Priority:    "medium",
			Category:    "update",
			Title:       "Update Outdated Dependencies",
			Description: fmt.Sprintf("%d dependencies have updates available", outdatedCount),
			Action:      "Review and update dependencies to latest versions",
			Impact:      "Improves compatibility and security",
			Effort:      "medium",
		})
	}

	return recommendations
}

// generateReputationRecommendations generates reputation-focused recommendations
func (rg *ReportGenerator) generateReputationRecommendations() []Recommendation {
	recommendations := make([]Recommendation, 0)

	if rg.repDB != nil {
		blacklistedCount := len(rg.repDB.GetBlacklistedPackages())
		if blacklistedCount > 0 {
			recommendations = append(recommendations, Recommendation{
				Priority:    "critical",
				Category:    "security",
				Title:       "Remove Blacklisted Packages",
				Description: fmt.Sprintf("%d blacklisted packages detected in dependencies", blacklistedCount),
				Action:      "Replace blacklisted packages with trusted alternatives",
				Impact:      "Eliminates untrusted dependencies",
				Effort:      "medium",
			})
		}
	}

	return recommendations
}

// generateThreatRecommendations generates threat-focused recommendations
func (rg *ReportGenerator) generateThreatRecommendations() []Recommendation {
	recs := append(
		rg.generateSecurityRecommendations(),
		rg.generateReputationRecommendations()...,
	)
	return recs
}

// generateComplianceRecommendations generates compliance-focused recommendations
func (rg *ReportGenerator) generateComplianceRecommendations() []Recommendation {
	return []Recommendation{
		{
			Priority:    "high",
			Category:    "compliance",
			Title:       "Establish Dependency Policy",
			Description: "Create a formal policy for dependency management and updates",
			Action:      "Document dependency governance process",
			Impact:      "Improves compliance and maintainability",
			Effort:      "medium",
		},
	}
}

// generateExecutiveSummary generates executive summary text
func (rg *ReportGenerator) generateExecutiveSummary(report *Report) string {
	if report.Summary == nil {
		return ""
	}

	summary := report.Summary
	sb := strings.Builder{}

	sb.WriteString(fmt.Sprintf("EXECUTIVE SUMMARY\n\n"))
	sb.WriteString(fmt.Sprintf("This report analyzes %d dependencies in your supply chain.\n\n", summary.TotalPackages))

	if summary.CriticalIssues > 0 {
		sb.WriteString(fmt.Sprintf("CRITICAL: %d critical issues require immediate attention.\n", summary.CriticalIssues))
	}

	sb.WriteString(fmt.Sprintf("Overall Risk Score: %.1f/100\n", summary.RiskScore))
	sb.WriteString(fmt.Sprintf("Compliance Score: %.1f/100\n", summary.ComplianceScore))

	if summary.SuspiciousPackages > 0 {
		sb.WriteString(fmt.Sprintf("\n⚠️  WARNING: %d suspicious packages detected.\n", summary.SuspiciousPackages))
	}

	sb.WriteString(fmt.Sprintf("\nTrusted Packages: %d (%.1f%%)\n", 
		summary.TrustedPackages, 
		float64(summary.TrustedPackages)/float64(summary.TotalPackages)*100))

	return sb.String()
}

// formatReport formats report to specified format
func (rg *ReportGenerator) formatReport(report *Report, format ReportFormat) string {
	switch format {
	case FormatJSON:
		data, _ := json.MarshalIndent(report, "", "  ")
		return string(data)

	case FormatHTML:
		return rg.formatHTML(report)

	case FormatCSV:
		return rg.formatCSV(report)

	case FormatText:
		fallthrough

	default:
		return rg.formatText(report)
	}
}

// formatHTML generates HTML format
func (rg *ReportGenerator) formatHTML(report *Report) string {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>` + report.Title + `</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #333; }
        h2 { color: #666; border-bottom: 2px solid #007bff; }
        .critical { color: #d9534f; font-weight: bold; }
        .high { color: #f0ad4e; }
        .medium { color: #5bc0de; }
        .low { color: #5cb85c; }
        table { border-collapse: collapse; width: 100%; margin: 10px 0; }
        td, th { border: 1px solid #ddd; padding: 8px; text-align: left; }
        th { background-color: #007bff; color: white; }
    </style>
</head>
<body>
    <h1>` + report.Title + `</h1>
    <p>Generated: ` + report.GeneratedAt.Format("2006-01-02 15:04:05") + `</p>`

	if report.Summary != nil {
		html += `<h2>Summary</h2>
        <p>Total Packages: ` + fmt.Sprintf("%d", report.Summary.TotalPackages) + `</p>
        <p>Risk Score: ` + fmt.Sprintf("%.1f", report.Summary.RiskScore) + `/100</p>
        <p class="critical">Critical Issues: ` + fmt.Sprintf("%d", report.Summary.CriticalIssues) + `</p>`
	}

	html += `</body></html>`
	return html
}

// formatCSV generates CSV format
func (rg *ReportGenerator) formatCSV(report *Report) string {
	csv := "Name,Version,Severity,Description\n"

	for _, vuln := range report.Vulnerabilities {
		csv += fmt.Sprintf("%s,%s,%s,%s\n", 
			vuln.PackageName,
			vuln.PackageVersion,
			vuln.Severity,
			vuln.Description)
	}

	return csv
}

// formatText generates text format
func (rg *ReportGenerator) formatText(report *Report) string {
	text := fmt.Sprintf("=== %s ===\n\n", report.Title)
	text += fmt.Sprintf("Generated: %s\n", report.GeneratedAt.Format("2006-01-02 15:04:05"))
	text += fmt.Sprintf("Type: %s\n\n", report.ReportType)

	if report.ExecutiveSummary != "" {
		text += report.ExecutiveSummary + "\n\n"
	}

	if report.Summary != nil {
		text += fmt.Sprintf("Total Packages: %d\n", report.Summary.TotalPackages)
		text += fmt.Sprintf("Risk Score: %.1f/100\n", report.Summary.RiskScore)
		text += fmt.Sprintf("Compliance Score: %.1f/100\n\n", report.Summary.ComplianceScore)
	}

	return text
}

// GetReportHistory returns all generated reports
func (rg *ReportGenerator) GetReportHistory() []*Report {
	rg.mu.RLock()
	defer rg.mu.RUnlock()

	result := make([]*Report, len(rg.generatedReports))
	copy(result, rg.generatedReports)
	return result
}

// GetReportCount returns the count of generated reports
func (rg *ReportGenerator) GetReportCount() int {
	rg.mu.RLock()
	defer rg.mu.RUnlock()

	return len(rg.generatedReports)
}

// ClearData clears all collected data
func (rg *ReportGenerator) ClearData() {
	rg.mu.Lock()
	defer rg.mu.Unlock()

	rg.anomalies = make([]*anomaly.Anomaly, 0)
	rg.dependencies = make(map[string]*DependencyEntry)
}

// Helper functions

func generateReportID() string {
	return fmt.Sprintf("report_%d", time.Now().UnixNano())
}

func calculateRiskScore(critical, high, medium, low int) float64 {
	score := float64(critical*40 + high*25 + medium*10 + low*5)
	if score > 100 {
		score = 100
	}
	return score
}

func calculateComplianceScore(trusted, total int) float64 {
	if total == 0 {
		return 100
	}
	return float64(trusted) / float64(total) * 100
}
