package tests

import (
	"testing"

	"github.com/Nash0810/TraceOrigin/pkg/anomaly"
	"github.com/Nash0810/TraceOrigin/pkg/correlator"
	"github.com/Nash0810/TraceOrigin/pkg/manifest"
)

// TestAnomalyDetectorCreation verifies detector initialization
func TestAnomalyDetectorCreation(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	if detector == nil {
		t.Fatal("Expected non-nil detector")
	}

	anomalies := detector.DetectAnomalies()
	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies for empty detector, got %d", len(anomalies))
	}

	if detector.GetAverageRiskLevel() != "low" {
		t.Errorf("Expected 'low' risk level for empty detector, got '%s'", detector.GetAverageRiskLevel())
	}
}

// TestBehavioralAnomalyDetection verifies detection of unusual download sources
func TestBehavioralAnomalyDetection(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chain := &correlator.DependencyChain{
		PackageName:     "flask",
		ActualVersion:   "2.0.1",
		DeclaredVersion: "2.0.1",
		DownloadURL:     "http://suspicious-domain.com/flask-2.0.1.tar.gz",
	}
	detector.AddChain(chain)

	declared := &manifest.DeclaredPackage{
		Name:       "flask",
		Version:    "2.0.1",
		Constraint: "==2.0.1",
	}
	detector.AddDeclaredPackage(declared)

	anomalies := detector.DetectAnomalies()

	if len(anomalies) == 0 {
		t.Fatal("Expected anomalies for unusual download source")
	}

	found := false
	for _, a := range anomalies {
		if a.PackageName == "flask" && a.AnomalyType == "behavioral" {
			found = true
		}
	}

	if !found {
		t.Error("Expected to find behavioral anomaly for flask")
	}
}

// TestBehavioralDeviationDetection verifies version mismatch detection
func TestBehavioralDeviationDetection(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chain := &correlator.DependencyChain{
		PackageName:     "django",
		ActualVersion:   "2.4.0",
		DeclaredVersion: "2.5.0",
		DownloadURL:     "https://files.pythonhosted.org/django-2.4.0.tar.gz",
	}
	detector.AddChain(chain)

	declared := &manifest.DeclaredPackage{
		Name:       "django",
		Version:    "2.5.0",
		Constraint: "==2.5.0",
	}
	detector.AddDeclaredPackage(declared)

	anomalies := detector.DetectAnomalies()

	found := false
	for _, a := range anomalies {
		if a.AnomalyType == "behavioral_deviation" && a.Severity == "critical" {
			found = true
		}
	}

	if !found {
		t.Error("Expected to find critical behavioral deviation for downgrade")
	}
}

// TestPatternAnomalyDetection verifies detection of typosquatting patterns
func TestPatternAnomalyDetection(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chain := &correlator.DependencyChain{
		PackageName:   "flak",
		ActualVersion: "2.0.1",
		DownloadURL:   "https://registry.npmjs.org/flak",
	}
	detector.AddChain(chain)

	anomalies := detector.DetectAnomalies()

	found := false
	for _, a := range anomalies {
		if a.AnomalyType == "pattern" && a.Severity == "critical" {
			found = true
		}
	}

	if !found {
		t.Error("Expected to find critical pattern anomaly for typosquatting")
	}
}

// TestDomainSwitchingDetection verifies detection of multiple registry domains
func TestDomainSwitchingDetection(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	domains := []string{
		"https://files.pythonhosted.org/pkg-1.0.tar.gz",
		"https://pypi.org/pkg-1.0.tar.gz",
		"https://custom-registry.com/pkg-1.0.tar.gz",
	}

	for _, domain := range domains {
		chain := &correlator.DependencyChain{
			PackageName:   "pkg",
			ActualVersion: "1.0",
			DownloadURL:   domain,
		}
		detector.AddChain(chain)
	}

	anomalies := detector.DetectAnomalies()

	found := false
	for _, a := range anomalies {
		if a.AnomalyType == "behavioral" {
			for _, indicator := range a.Indicators {
				if indicator == "domain_switching" {
					found = true
					break
				}
			}
		}
	}

	if !found {
		t.Error("Expected to find domain switching anomaly")
	}
}

// TestThreatScoreCalculation verifies threat score computation
func TestThreatScoreCalculation(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chain := &correlator.DependencyChain{
		PackageName:   "test-pkg",
		ActualVersion: "1.0.0",
		DownloadURL:   "http://malicious.com/test-pkg-1.0.0.tar.gz",
	}
	detector.AddChain(chain)

	anomalies := detector.DetectAnomalies()

	if len(anomalies) == 0 {
		t.Fatal("Expected anomalies")
	}

	for _, a := range anomalies {
		if a.ThreatScore < 0 || a.ThreatScore > 100 {
			t.Errorf("Expected threat score between 0 and 100, got %.2f", a.ThreatScore)
		}
	}
}

// TestGetAnomaliesBySeverity verifies severity filtering
func TestGetAnomaliesBySeverity(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chains := []*correlator.DependencyChain{
		{
			PackageName:   "flak",
			ActualVersion: "1.0",
			DownloadURL:   "https://registry.npmjs.org/flak",
		},
		{
			PackageName:   "flask",
			ActualVersion: "1.0",
			DownloadURL:   "http://unusual-domain.com/flask",
		},
	}

	for _, chain := range chains {
		detector.AddChain(chain)
	}

	_ = detector.DetectAnomalies()

	criticalAnomalies := detector.GetAnomaliesBySeverity("critical")

	if len(criticalAnomalies) == 0 {
		t.Error("Expected critical anomalies")
	}

	for _, a := range criticalAnomalies {
		if a.Severity != "critical" {
			t.Errorf("Expected critical severity, got '%s'", a.Severity)
		}
	}
}

// TestGetAnomaliesByPackage verifies package filtering
func TestGetAnomaliesByPackage(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chain := &correlator.DependencyChain{
		PackageName:   "specific-package",
		ActualVersion: "1.0.0",
		DownloadURL:   "http://malicious.com/pkg",
	}
	detector.AddChain(chain)

	_ = detector.DetectAnomalies()

	pkgAnomalies := detector.GetAnomaliesByPackage("specific-package")

	if len(pkgAnomalies) == 0 {
		t.Error("Expected anomalies for specific package")
	}

	for _, a := range pkgAnomalies {
		if a.PackageName != "specific-package" {
			t.Errorf("Expected package name 'specific-package', got '%s'", a.PackageName)
		}
	}
}

// TestRiskLevelAssessment verifies overall risk assessment
func TestRiskLevelAssessment(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chain := &correlator.DependencyChain{
		PackageName:     "standard-lib",
		ActualVersion:   "1.0.0",
		DeclaredVersion: "1.0.0",
		DownloadURL:     "https://files.pythonhosted.org/standard-lib-1.0.0.tar.gz",
	}
	detector.AddChain(chain)

	declared := &manifest.DeclaredPackage{
		Name:       "standard-lib",
		Version:    "1.0.0",
		Constraint: "==1.0.0",
	}
	detector.AddDeclaredPackage(declared)

	_ = detector.DetectAnomalies()

	riskLevel := detector.GetAverageRiskLevel()
	if riskLevel != "low" {
		t.Errorf("Expected 'low' risk for clean scenario, got '%s'", riskLevel)
	}
}

// TestAnomalyRemediationSuggestions verifies remediation guidance
func TestAnomalyRemediationSuggestions(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chain := &correlator.DependencyChain{
		PackageName:   "suspect",
		ActualVersion: "1.0.0",
		DownloadURL:   "http://untrusted.com/suspect",
	}
	detector.AddChain(chain)

	anomalies := detector.DetectAnomalies()

	for _, a := range anomalies {
		if a.Remediation == "" {
			t.Errorf("Expected remediation guidance for anomaly type %s", a.AnomalyType)
		}
	}
}

// TestAnomalySummary verifies summary generation
func TestAnomalySummary(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chains := []*correlator.DependencyChain{
		{
			PackageName:   "pkg1",
			ActualVersion: "1.0",
			DownloadURL:   "http://malicious.com/pkg1",
		},
		{
			PackageName:   "pkg2",
			ActualVersion: "1.0",
			DownloadURL:   "http://malicious.com/pkg2",
		},
	}

	for _, chain := range chains {
		detector.AddChain(chain)
	}

	_ = detector.DetectAnomalies()
	summary := detector.GetSummary()

	if summary["total_anomalies"] == nil {
		t.Error("Expected total_anomalies in summary")
	}

	if summary["by_severity"] == nil {
		t.Error("Expected by_severity in summary")
	}

	if summary["by_type"] == nil {
		t.Error("Expected by_type in summary")
	}

	if summary["average_risk_level"] == nil {
		t.Error("Expected average_risk_level in summary")
	}
}

// TestUnusualVersionPattern verifies prerelease detection
func TestUnusualVersionPattern(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chain := &correlator.DependencyChain{
		PackageName:   "pkg",
		ActualVersion: "1.0.0-alpha1",
		DownloadURL:   "https://files.pythonhosted.org/pkg",
	}
	detector.AddChain(chain)

	anomalies := detector.DetectAnomalies()

	found := false
	for _, a := range anomalies {
		if a.AnomalyType == "behavioral" {
			for _, indicator := range a.Indicators {
				if indicator == "prerelease_version" {
					found = true
					break
				}
			}
		}
	}

	if !found {
		t.Error("Expected to find prerelease version anomaly")
	}
}

// TestMultipleAnomaliesPerPackage verifies handling of multiple issues
func TestMultipleAnomaliesPerPackage(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chain := &correlator.DependencyChain{
		PackageName:   "problematic",
		ActualVersion: "2.0.0-rc1",
		DownloadURL:   "http://untrusted.com/problematic",
	}
	detector.AddChain(chain)

	anomalies := detector.DetectAnomalies()

	if len(anomalies) < 2 {
		t.Errorf("Expected at least 2 anomalies for problematic package, got %d", len(anomalies))
	}
}

// TestConfidenceLevels verifies confidence scoring
func TestConfidenceLevels(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	chain := &correlator.DependencyChain{
		PackageName:   "test",
		ActualVersion: "1.0",
		DownloadURL:   "http://bad.com/test",
	}
	detector.AddChain(chain)

	anomalies := detector.DetectAnomalies()

	for _, a := range anomalies {
		if a.Confidence < 0 || a.Confidence > 1 {
			t.Errorf("Expected confidence between 0 and 1, got %.2f", a.Confidence)
		}
	}
}

// BenchmarkAnomalyDetection measures anomaly detection performance
func BenchmarkAnomalyDetection(b *testing.B) {
	detector := anomaly.NewAnomalyDetector()

	for i := 0; i < 100; i++ {
		chain := &correlator.DependencyChain{
			PackageName:   "benchmark-pkg",
			ActualVersion: "1.0.0",
			DownloadURL:   "https://files.pythonhosted.org/benchmark-pkg",
		}
		detector.AddChain(chain)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = detector.DetectAnomalies()
	}
}

// TestEmptyDetectorScenarios verifies handling of edge cases
func TestEmptyDetectorScenarios(t *testing.T) {
	detector := anomaly.NewAnomalyDetector()

	anomalies := detector.DetectAnomalies()
	if len(anomalies) != 0 {
		t.Errorf("Expected 0 anomalies for empty detector, got %d", len(anomalies))
	}

	criticalAnomalies := detector.GetAnomaliesBySeverity("critical")
	if len(criticalAnomalies) != 0 {
		t.Error("Expected no critical anomalies for empty detector")
	}

	pkgAnomalies := detector.GetAnomaliesByPackage("nonexistent")
	if len(pkgAnomalies) != 0 {
		t.Error("Expected no anomalies for nonexistent package")
	}

	score := detector.GetThreatScore("nonexistent")
	if score != 0 {
		t.Errorf("Expected threat score 0 for nonexistent package, got %.2f", score)
	}
}
