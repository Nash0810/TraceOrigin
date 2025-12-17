package tests

import (
	"fmt"
	"strings"
	"testing"

	"github.com/Nash0810/TraceOrigin/pkg/anomaly"
	"github.com/Nash0810/TraceOrigin/pkg/report"
	"github.com/Nash0810/TraceOrigin/pkg/reputation"
)

func TestReportGeneratorCreation(t *testing.T) {
	repDB := reputation.NewReputationDatabase()
	gen := report.NewReportGenerator(repDB)

	if gen == nil {
		t.Error("ReportGenerator creation failed")
	}

	if gen.GetReportCount() != 0 {
		t.Error("New generator should have no reports")
	}
}

func TestAddAnomaly(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	anom := &anomaly.Anomaly{
		PackageName: "test-pkg",
		Severity:    "critical",
		ThreatScore: 85.0,
	}

	gen.AddAnomaly(anom)

	// Test nil anomaly doesn't crash
	gen.AddAnomaly(nil)
}

func TestAddDependency(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	dep := &report.DependencyEntry{
		Name:             "express",
		InstalledVersion: "4.18.0",
		LatestVersion:    "4.19.0",
		UpdateAvailable:  true,
		TrustLevel:       "trusted",
		Depth:            0,
	}

	err := gen.AddDependency(dep)
	if err != nil {
		t.Errorf("Failed to add dependency: %v", err)
	}

	// Test nil dependency
	err = gen.AddDependency(nil)
	if err == nil {
		t.Error("Should reject nil dependency")
	}

	// Test empty name
	emptyDep := &report.DependencyEntry{}
	err = gen.AddDependency(emptyDep)
	if err == nil {
		t.Error("Should reject dependency with empty name")
	}
}

func TestSetMetadata(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	gen.SetMetadata("project_name", "supply-tracer")
	gen.SetMetadata("scan_date", "2024-12-17")
}

func TestGenerateSummaryReport(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	// Add test data
	anom := &anomaly.Anomaly{
		PackageName: "lodash",
		Severity:    "critical",
		ThreatScore: 90.0,
		Description: "Prototype pollution vulnerability",
	}
	gen.AddAnomaly(anom)

	dep := &report.DependencyEntry{
		Name:             "lodash",
		InstalledVersion: "4.17.20",
		TrustLevel:       "trusted",
	}
	gen.AddDependency(dep)

	rep, err := gen.GenerateReport(report.TypeSummary, report.FormatJSON)
	if err != nil {
		t.Errorf("Failed to generate report: %v", err)
	}

	if rep == nil {
		t.Error("Report should not be nil")
	}

	if rep.Summary == nil {
		t.Error("Report summary should not be nil")
	}

	if rep.Summary.CriticalIssues != 1 {
		t.Errorf("Expected 1 critical issue, got %d", rep.Summary.CriticalIssues)
	}
}

func TestGenerateVulnerabilityReport(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	anomalies := []*anomaly.Anomaly{
		{
			PackageName: "lodash",
			Severity:    "critical",
			AnomalyType: "prototype-pollution",
			Description: "Prototype pollution in lodash",
		},
		{
			PackageName: "express",
			Severity:    "high",
			AnomalyType: "xss-vulnerability",
			Description: "XSS in express routing",
		},
	}

	for _, anom := range anomalies {
		gen.AddAnomaly(anom)
	}

	rep, err := gen.GenerateReport(report.TypeVulnerability, report.FormatJSON)
	if err != nil {
		t.Errorf("Failed to generate vulnerability report: %v", err)
	}

	if len(rep.Vulnerabilities) != 2 {
		t.Errorf("Expected 2 vulnerabilities, got %d", len(rep.Vulnerabilities))
	}

	if len(rep.Recommendations) == 0 {
		t.Error("Should have recommendations")
	}
}

func TestGenerateDependencyReport(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	deps := []*report.DependencyEntry{
		{
			Name:             "express",
			InstalledVersion: "4.18.0",
			LatestVersion:    "4.19.0",
			UpdateAvailable:  true,
			Depth:            0,
		},
		{
			Name:             "lodash",
			InstalledVersion: "4.17.20",
			LatestVersion:    "4.17.21",
			UpdateAvailable:  true,
			Depth:            1,
			IsTransitive:     true,
		},
	}

	for _, dep := range deps {
		gen.AddDependency(dep)
	}

	rep, err := gen.GenerateReport(report.TypeDependency, report.FormatJSON)
	if err != nil {
		t.Errorf("Failed to generate dependency report: %v", err)
	}

	if len(rep.Dependencies) != 2 {
		t.Errorf("Expected 2 dependencies, got %d", len(rep.Dependencies))
	}

	if rep.Statistics == nil {
		t.Error("Statistics should not be nil")
	}

	if rep.Statistics.TotalDependencies != 2 {
		t.Errorf("Expected 2 total dependencies, got %d", rep.Statistics.TotalDependencies)
	}
}

func TestGenerateReputationReport(t *testing.T) {
	repDB := reputation.NewReputationDatabase()

	// Add trusted package
	trustedPkg := &reputation.PackageReputation{
		Name:            "lodash",
		PackageManager:  "npm",
		ReputationScore: 90.0,
		TrustLevel:      reputation.TrustedLevel,
	}
	repDB.AddPackage(trustedPkg)

	gen := report.NewReportGenerator(repDB)

	dep := &report.DependencyEntry{
		Name:             "lodash",
		InstalledVersion: "4.17.21",
	}
	gen.AddDependency(dep)

	rep, err := gen.GenerateReport(report.TypeReputation, report.FormatJSON)
	if err != nil {
		t.Errorf("Failed to generate reputation report: %v", err)
	}

	if rep.Reputation == nil {
		t.Error("Reputation analysis should not be nil")
	}

	if rep.Reputation.TrustedPercentage == 0 {
		t.Error("Should have trusted percentage")
	}
}

func TestReportFormats(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	dep := &report.DependencyEntry{
		Name:             "test-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	formats := []report.ReportFormat{
		report.FormatJSON,
		report.FormatHTML,
		report.FormatCSV,
		report.FormatText,
	}

	for _, format := range formats {
		rep, err := gen.GenerateReport(report.TypeSummary, format)
		if err != nil {
			t.Errorf("Failed to generate %s report: %v", format, err)
		}

		if rep.Format != format {
			t.Errorf("Expected format %s, got %s", format, rep.Format)
		}

		if rep.Content == "" {
			t.Errorf("Content should not be empty for format %s", format)
		}
	}
}

func TestReportTypes(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	anom := &anomaly.Anomaly{
		PackageName: "test-pkg",
		Severity:    "high",
		AnomalyType: "vulnerability",
	}
	gen.AddAnomaly(anom)

	dep := &report.DependencyEntry{
		Name:             "test-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	reportTypes := []report.ReportType{
		report.TypeSummary,
		report.TypeVulnerability,
		report.TypeDependency,
		report.TypeThreatAnalysis,
		report.TypeCompliance,
	}

	for _, reportType := range reportTypes {
		rep, err := gen.GenerateReport(reportType, report.FormatJSON)
		if err != nil {
			t.Errorf("Failed to generate %s report: %v", reportType, err)
		}

		if rep.ReportType != reportType {
			t.Errorf("Expected report type %s, got %s", reportType, rep.ReportType)
		}
	}
}

func TestExecutiveSummary(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	anom := &anomaly.Anomaly{
		PackageName: "critical-pkg",
		Severity:    "critical",
		ThreatScore: 95.0,
	}
	gen.AddAnomaly(anom)

	dep := &report.DependencyEntry{
		Name:             "critical-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	rep, _ := gen.GenerateReport(report.TypeVulnerability, report.FormatText)

	if rep.ExecutiveSummary == "" {
		t.Error("Executive summary should not be empty")
	}

	if !strings.Contains(rep.ExecutiveSummary, "critical") {
		t.Error("Executive summary should mention critical issues")
	}
}

func TestReportMetadata(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	gen.SetMetadata("project", "test-project")
	gen.SetMetadata("environment", "production")

	dep := &report.DependencyEntry{
		Name:             "test-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	rep, _ := gen.GenerateReport(report.TypeSummary, report.FormatJSON)

	if rep.Metadata["project"] != "test-project" {
		t.Error("Metadata not set correctly")
	}

	if rep.Metadata["environment"] != "production" {
		t.Error("Metadata not set correctly")
	}
}

func TestGetReportHistory(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	dep := &report.DependencyEntry{
		Name:             "test-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	// Generate multiple reports
	for i := 0; i < 3; i++ {
		_, err := gen.GenerateReport(report.TypeSummary, report.FormatJSON)
		if err != nil {
			t.Errorf("Failed to generate report: %v", err)
		}
	}

	if gen.GetReportCount() != 3 {
		t.Errorf("Expected 3 reports, got %d", gen.GetReportCount())
	}

	history := gen.GetReportHistory()
	if len(history) != 3 {
		t.Errorf("Expected 3 reports in history, got %d", len(history))
	}
}

func TestRiskScoreCalculation(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	// Add critical anomalies
	for i := 0; i < 2; i++ {
		anom := &anomaly.Anomaly{
			PackageName: fmt.Sprintf("pkg-%d", i),
			Severity:    "critical",
		}
		gen.AddAnomaly(anom)

		dep := &report.DependencyEntry{
			Name:             fmt.Sprintf("pkg-%d", i),
			InstalledVersion: "1.0.0",
		}
		gen.AddDependency(dep)
	}

	rep, _ := gen.GenerateReport(report.TypeSummary, report.FormatJSON)

	if rep.Summary.RiskScore == 0 {
		t.Error("Risk score should be calculated")
	}

	if rep.Summary.RiskScore > 100 {
		t.Error("Risk score should not exceed 100")
	}
}

func TestComplianceScoreCalculation(t *testing.T) {
	repDB := reputation.NewReputationDatabase()

	// Add trusted packages
	for i := 0; i < 2; i++ {
		pkg := &reputation.PackageReputation{
			Name:            fmt.Sprintf("trusted-%d", i),
			PackageManager:  "npm",
			ReputationScore: 90.0,
			TrustLevel:      reputation.TrustedLevel,
		}
		repDB.AddPackage(pkg)
	}

	gen := report.NewReportGenerator(repDB)

	// Add dependencies
	for i := 0; i < 3; i++ {
		dep := &report.DependencyEntry{
			Name:             fmt.Sprintf("pkg-%d", i),
			InstalledVersion: "1.0.0",
		}
		gen.AddDependency(dep)
	}

	rep, _ := gen.GenerateReport(report.TypeSummary, report.FormatJSON)

	if rep.Summary.ComplianceScore == 0 && rep.Summary.TrustedPackages > 0 {
		t.Error("Compliance score should be calculated")
	}
}

func TestClearData(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	dep := &report.DependencyEntry{
		Name:             "test-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	anom := &anomaly.Anomaly{
		PackageName: "test-pkg",
		Severity:    "high",
	}
	gen.AddAnomaly(anom)

	gen.ClearData()

	// Generate report should fail now
	_, err := gen.GenerateReport(report.TypeSummary, report.FormatJSON)
	if err == nil {
		t.Error("Should fail to generate report after clearing data")
	}
}

func TestRecommendations(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	// Add high-severity anomaly
	anom := &anomaly.Anomaly{
		PackageName: "vulnerable-pkg",
		Severity:    "critical",
	}
	gen.AddAnomaly(anom)

	// Add outdated dependency
	dep := &report.DependencyEntry{
		Name:             "outdated-pkg",
		InstalledVersion: "1.0.0",
		LatestVersion:    "2.0.0",
		UpdateAvailable:  true,
	}
	gen.AddDependency(dep)

	rep, _ := gen.GenerateReport(report.TypeThreatAnalysis, report.FormatJSON)

	if len(rep.Recommendations) == 0 {
		t.Error("Should have recommendations")
	}

	// Check for critical recommendation
	hasCritical := false
	for _, rec := range rep.Recommendations {
		if rec.Priority == "critical" {
			hasCritical = true
			break
		}
	}

	if !hasCritical {
		t.Error("Should have critical-priority recommendation")
	}
}

func TestEmptyReportError(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	_, err := gen.GenerateReport(report.TypeSummary, report.FormatJSON)
	if err == nil {
		t.Error("Should error when no data to report")
	}
}

func TestHTMLFormatOutput(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	dep := &report.DependencyEntry{
		Name:             "test-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	rep, _ := gen.GenerateReport(report.TypeSummary, report.FormatHTML)

	if !strings.Contains(rep.Content, "<!DOCTYPE html>") {
		t.Error("HTML report should contain HTML doctype")
	}

	if !strings.Contains(rep.Content, "<title>") {
		t.Error("HTML report should have title")
	}
}

func TestCSVFormatOutput(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	anom := &anomaly.Anomaly{
		PackageName: "test-pkg",
		Severity:    "high",
		Description: "Test vulnerability",
	}
	gen.AddAnomaly(anom)

	rep, _ := gen.GenerateReport(report.TypeVulnerability, report.FormatCSV)

	if !strings.Contains(rep.Content, "Name,Version,Severity,Description") {
		t.Error("CSV report should have header")
	}
}

func TestTextFormatOutput(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	dep := &report.DependencyEntry{
		Name:             "test-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	rep, _ := gen.GenerateReport(report.TypeSummary, report.FormatText)

	if !strings.Contains(rep.Content, "===") {
		t.Error("Text report should have header")
	}

	if !strings.Contains(rep.Content, "Generated:") {
		t.Error("Text report should have generation date")
	}
}

func TestConcurrentReportGeneration(t *testing.T) {
	gen := report.NewReportGenerator(nil)

	dep := &report.DependencyEntry{
		Name:             "test-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	// Generate reports concurrently
	done := make(chan bool, 5)

	for i := 0; i < 5; i++ {
		go func(idx int) {
			_, err := gen.GenerateReport(report.TypeSummary, report.FormatJSON)
			if err != nil {
				t.Errorf("Failed to generate report: %v", err)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 5; i++ {
		<-done
	}

	if gen.GetReportCount() != 5 {
		t.Errorf("Expected 5 reports, got %d", gen.GetReportCount())
	}
}

// Benchmarks

func BenchmarkGenerateSummaryReport(b *testing.B) {
	gen := report.NewReportGenerator(nil)

	dep := &report.DependencyEntry{
		Name:             "test-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.GenerateReport(report.TypeSummary, report.FormatJSON)
	}
}

func BenchmarkAddDependency(b *testing.B) {
	gen := report.NewReportGenerator(nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dep := &report.DependencyEntry{
			Name:             fmt.Sprintf("pkg-%d", i),
			InstalledVersion: "1.0.0",
		}
		gen.AddDependency(dep)
	}
}

func BenchmarkFormatJSON(b *testing.B) {
	gen := report.NewReportGenerator(nil)

	dep := &report.DependencyEntry{
		Name:             "test-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	rep, _ := gen.GenerateReport(report.TypeSummary, report.FormatJSON)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = rep.Content
	}
}

func BenchmarkFormatHTML(b *testing.B) {
	gen := report.NewReportGenerator(nil)

	dep := &report.DependencyEntry{
		Name:             "test-pkg",
		InstalledVersion: "1.0.0",
	}
	gen.AddDependency(dep)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gen.GenerateReport(report.TypeSummary, report.FormatHTML)
	}
}
