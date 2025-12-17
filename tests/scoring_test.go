package tests

import (
	"fmt"
	"testing"

	"github.com/Nash0810/TraceOrigin/pkg/scoring"
)

func TestScoringEngineCreation(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()
	if engine == nil {
		t.Fatal("failed to create threat scoring engine")
	}
}

func TestScorePackage(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "requests",
		Version:            "2.28.0",
		DownloadDomain:     "files.pythonhosted.org",
		IsTyposquatting:    false,
		TyposquattingScore: 0.0,
		VersionMismatch:    false,
		IsSigned:           true,
		ReputationScore:    85.0,
		DownloadCount:      50000,
		Age:                1000,
		IsMaintained:       true,
		AssociatedCVEs:     []string{},
		DownloadSourceCount: 1,
		IsFromOfficialRepo: true,
		Metadata:           map[string]interface{}{"test": true},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score package: %v", err)
	}

	if score.PackageName != "requests" {
		t.Errorf("package name mismatch: %s", score.PackageName)
	}
	if score.Score < 0 || score.Score > 100 {
		t.Errorf("score out of range: %f", score.Score)
	}
	if score.ThreatLevel == "" {
		t.Error("threat level not set")
	}
}

func TestTyposquattingDetection(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "reqeusts",
		Version:            "1.0.0",
		DownloadDomain:     "malicious.com",
		IsTyposquatting:    true,
		TyposquattingScore: 0.8,
		IsSigned:           false,
		ReputationScore:    10.0,
		DownloadCount:      5,
		Age:                2,
		IsFromOfficialRepo: false,
		Metadata:           map[string]interface{}{},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score typosquatting package: %v", err)
	}

	// Verify typosquatting factor is calculated
	if score.Factors[scoring.RiskFactorTyposquatting] < 30 {
		t.Errorf("typosquatting factor too low: %f", score.Factors[scoring.RiskFactorTyposquatting])
	}

	// Verify we got a valid threat level
	if score.ThreatLevel == "" {
		t.Error("expected threat level to be assigned")
	}

	if len(score.Recommendations) == 0 {
		t.Error("expected recommendations for typosquatting")
	}
}

func TestVersionMismatchScoring(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "flask",
		Version:            "2.0.0",
		VersionMismatch:    true,
		IsSigned:           true,
		ReputationScore:    70.0,
		DownloadCount:      30000,
		Age:                500,
		IsFromOfficialRepo: true,
		Metadata:           map[string]interface{}{},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score package with version mismatch: %v", err)
	}

	if score.Factors[scoring.RiskFactorVersionMismatch] == 0 {
		t.Error("version mismatch factor not calculated")
	}
}

func TestUnsignedPackageScoring(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "some-package",
		Version:            "1.0.0",
		IsSigned:           false,
		ReputationScore:    60.0,
		DownloadCount:      100,
		Age:                30,
		IsFromOfficialRepo: true,
		Metadata:           map[string]interface{}{},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score unsigned package: %v", err)
	}

	if score.Factors[scoring.RiskFactorUnsignedPackage] == 0 {
		t.Error("unsigned package factor not calculated")
	}
}

func TestLowReputationScoring(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "low-rep-package",
		Version:            "1.0.0",
		ReputationScore:    15.0,
		IsSigned:           true,
		DownloadCount:      200,
		Age:                60,
		IsFromOfficialRepo: true,
		Metadata:           map[string]interface{}{},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score low reputation package: %v", err)
	}

	if score.Factors[scoring.RiskFactorReputationLow] < 10 {
		t.Errorf("reputation factor too low: %f", score.Factors[scoring.RiskFactorReputationLow])
	}
}

func TestNewPackageScoring(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "brand-new-package",
		Version:            "0.1.0",
		Age:                2,
		DownloadCount:      500,
		IsSigned:           true,
		ReputationScore:    50.0,
		IsFromOfficialRepo: true,
		Metadata:           map[string]interface{}{},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score new package: %v", err)
	}

	if score.Factors[scoring.RiskFactorNewPackage] == 0 {
		t.Error("new package factor not calculated")
	}
}

func TestCVEAssociationScoring(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	// Test with multiple risk factors to ensure proper scoring
	input := scoring.RiskFactorInput{
		PackageName:        "vulnerable-package",
		Version:            "1.0.0",
		DownloadDomain:     "untrusted.com",
		IsTyposquatting:    true,
		TyposquattingScore: 0.3,
		AssociatedCVEs:     []string{"CVE-2021-12345", "CVE-2021-12346"},
		IsSigned:           false,
		ReputationScore:    20.0,
		DownloadCount:      100,
		Age:                10,
		IsMaintained:       false,
		IsFromOfficialRepo: false,
		Metadata:           map[string]interface{}{},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score package with CVEs: %v", err)
	}

	// Verify CVE factor is calculated
	if score.Factors[scoring.RiskFactorCVEAssociated] < 25 {
		t.Errorf("CVE factor too low: %f", score.Factors[scoring.RiskFactorCVEAssociated])
	}

	// With multiple risk factors, score should be moderate to high
	if score.Score < 15 {
		t.Errorf("expected meaningful threat score with CVEs, got %f", score.Score)
	}
}

func TestNonStandardRepoScoring(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "custom-package",
		Version:            "1.0.0",
		IsFromOfficialRepo: false,
		IsSigned:           false,
		ReputationScore:    30.0,
		DownloadCount:      10,
		Age:                5,
		Metadata:           map[string]interface{}{},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score package from non-standard repo: %v", err)
	}

	if score.Factors[scoring.RiskFactorNonStandardRepo] == 0 {
		t.Error("non-standard repo factor not calculated")
	}
}

func TestDownloadAnomalyDetection(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "suspicious-package",
		Version:            "1.0.0",
		DownloadSourceCount: 5,
		DownloadCount:      2,
		Age:                 60,
		IsSigned:            true,
		ReputationScore:     40.0,
		IsFromOfficialRepo:  true,
		Metadata:            map[string]interface{}{},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score package with download anomalies: %v", err)
	}

	if score.Factors[scoring.RiskFactorDownloadAnomalies] == 0 {
		t.Error("download anomaly factor not calculated")
	}
}

func TestMissingPackageName(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName: "",
		Version:     "1.0.0",
	}

	_, err := engine.ScorePackage(input)
	if err == nil {
		t.Fatal("expected error for missing package name")
	}
}

func TestGetScore(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "test-package",
		Version:            "1.0.0",
		IsSigned:           true,
		ReputationScore:    75.0,
		DownloadCount:      1000,
		Age:                100,
		IsFromOfficialRepo: true,
		Metadata:           map[string]interface{}{},
	}

	original, _ := engine.ScorePackage(input)

	retrieved, exists := engine.GetScore("test-package", "1.0.0")
	if !exists {
		t.Fatal("score not found after retrieval")
	}

	if retrieved.Score != original.Score {
		t.Errorf("retrieved score mismatch: %f vs %f", retrieved.Score, original.Score)
	}
}

func TestGetScoreHistory(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	pkgName := "history-package"

	for i := 1; i <= 5; i++ {
		input := scoring.RiskFactorInput{
			PackageName:        pkgName,
			Version:            fmt.Sprintf("1.%d.0", i),
			IsSigned:           true,
			ReputationScore:    float64(50 + i*5),
			DownloadCount:      int64(100 * i),
			Age:                50 + i*10,
			IsFromOfficialRepo: true,
			Metadata:           map[string]interface{}{},
		}
		engine.ScorePackage(input)
	}

	history := engine.GetScoreHistory(pkgName)
	if len(history) != 5 {
		t.Errorf("expected 5 historical scores, got %d", len(history))
	}
}

func TestGetScoresByThreatLevel(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	risky := scoring.RiskFactorInput{
		PackageName:        "risky-pkg",
		Version:            "1.0.0",
		DownloadDomain:     "malicious.com",
		IsTyposquatting:    true,
		TyposquattingScore: 0.9,
		AssociatedCVEs:     []string{"CVE-2021-1", "CVE-2021-2"},
		IsSigned:           false,
		ReputationScore:    5.0,
		DownloadCount:      10,
		Age:                1,
		IsFromOfficialRepo: false,
		Metadata:           map[string]interface{}{},
	}
	riskyScore, _ := engine.ScorePackage(risky)

	safe := scoring.RiskFactorInput{
		PackageName:        "safe-pkg",
		Version:            "1.0.0",
		DownloadDomain:     "files.pythonhosted.org",
		IsSigned:           true,
		ReputationScore:    95.0,
		DownloadCount:      50000,
		Age:                500,
		IsFromOfficialRepo: true,
		Metadata:           map[string]interface{}{},
	}
	_, _ = engine.ScorePackage(safe)

	// Get all threat levels and verify we have at least one score
	allLevels := []scoring.ThreatLevel{
		scoring.ThreatLevelCritical,
		scoring.ThreatLevelHigh,
		scoring.ThreatLevelMedium,
		scoring.ThreatLevelLow,
		scoring.ThreatLevelInfo,
	}

	hasAnyScore := false
	for _, level := range allLevels {
		if len(engine.GetScoresByThreatLevel(level)) > 0 {
			hasAnyScore = true
			break
		}
	}

	if !hasAnyScore {
		t.Error("expected to find at least one score at some threat level")
	}

	// Verify that risky score is captured and has a threat level
	if riskyScore.ThreatLevel == "" {
		t.Error("risky score should have threat level assigned")
	}
}

func TestGetHighestRiskScores(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	for i := 1; i <= 10; i++ {
		input := scoring.RiskFactorInput{
			PackageName:        fmt.Sprintf("pkg%d", i),
			Version:            "1.0.0",
			ReputationScore:    float64((i * 8) % 100),
			IsSigned:           i%2 == 0,
			DownloadCount:      int64(100 * i),
			Age:                50,
			IsFromOfficialRepo: true,
			Metadata:           map[string]interface{}{},
		}
		engine.ScorePackage(input)
	}

	topScores := engine.GetHighestRiskScores(5)
	if len(topScores) != 5 {
		t.Errorf("expected 5 top scores, got %d", len(topScores))
	}

	for i := 1; i < len(topScores); i++ {
		if topScores[i].Score > topScores[i-1].Score {
			t.Errorf("scores not in descending order: %f > %f", topScores[i].Score, topScores[i-1].Score)
		}
	}
}

func TestUpdateWeights(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	newWeights := map[scoring.RiskFactor]float64{
		scoring.RiskFactorTyposquatting: 0.25,
		scoring.RiskFactorCVEAssociated: 0.20,
	}

	engine.UpdateWeights(newWeights)

	weights := engine.GetWeights()
	if weights[scoring.RiskFactorTyposquatting] != 0.25 {
		t.Errorf("weight not updated: %f", weights[scoring.RiskFactorTyposquatting])
	}
}

func TestGetStatistics(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	for i := 1; i <= 5; i++ {
		input := scoring.RiskFactorInput{
			PackageName:        fmt.Sprintf("stat-pkg%d", i),
			Version:            "1.0.0",
			ReputationScore:    float64(50 + i*10),
			IsSigned:           true,
			DownloadCount:      int64(1000),
			Age:                100,
			IsFromOfficialRepo: true,
			Metadata:           map[string]interface{}{},
		}
		engine.ScorePackage(input)
	}

	stats := engine.GetStatistics()

	if stats["total_scores"] != 5 {
		t.Errorf("expected 5 total scores in stats, got %v", stats["total_scores"])
	}

	if _, exists := stats["average_score"]; !exists {
		t.Error("average score not in statistics")
	}

	if _, exists := stats["critical_count"]; !exists {
		t.Error("critical count not in statistics")
	}
}

func TestThreatLevelThresholds(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	// Test that threat levels are calculated based on score
	highRiskInput := scoring.RiskFactorInput{
		PackageName:        "high-risk-pkg",
		Version:            "1.0.0",
		DownloadDomain:     "malicious.com",
		IsTyposquatting:    true,
		TyposquattingScore: 0.7,
		AssociatedCVEs:     []string{"CVE-2021-1"},
		ReputationScore:    15.0,
		IsFromOfficialRepo: false,
		IsSigned:           false,
		DownloadCount:      10,
		Age:                1,
		Metadata:           map[string]interface{}{},
	}

	lowRiskInput := scoring.RiskFactorInput{
		PackageName:        "low-risk-pkg",
		Version:            "1.0.0",
		DownloadDomain:     "files.pythonhosted.org",
		ReputationScore:    95.0,
		IsFromOfficialRepo: true,
		IsSigned:           true,
		DownloadCount:      50000,
		Age:                500,
		Metadata:           map[string]interface{}{},
	}

	highScore, err := engine.ScorePackage(highRiskInput)
	if err != nil {
		t.Fatalf("failed to score high risk package: %v", err)
	}

	lowScore, err := engine.ScorePackage(lowRiskInput)
	if err != nil {
		t.Fatalf("failed to score low risk package: %v", err)
	}

	// Verify that high risk package has higher score than low risk
	if highScore.Score <= lowScore.Score {
		t.Errorf("high risk score (%f) should be > low risk score (%f)", highScore.Score, lowScore.Score)
	}

	// Verify threat levels are assigned
	if highScore.ThreatLevel == "" {
		t.Error("high risk package should have threat level assigned")
	}
	if lowScore.ThreatLevel == "" {
		t.Error("low risk package should have threat level assigned")
	}
}

func TestRecommendationGeneration(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "risky-pkg",
		Version:            "1.0.0",
		IsTyposquatting:    true,
		TyposquattingScore: 0.8,
		IsSigned:           false,
		ReputationScore:    20.0,
		AssociatedCVEs:     []string{"CVE-2021-12345"},
		DownloadSourceCount: 4,
		IsFromOfficialRepo: false,
		Metadata:           map[string]interface{}{},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score package: %v", err)
	}

	if len(score.Recommendations) == 0 {
		t.Error("expected recommendations but got none")
	}

	hasTypoRec := false
	for _, rec := range score.Recommendations {
		if rec != "" {
			hasTypoRec = true
			break
		}
	}
	if !hasTypoRec {
		t.Error("expected at least one non-empty recommendation")
	}
}

func TestConfidenceCalculation(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "confidence-pkg",
		Version:            "1.0.0",
		IsSigned:           true,
		ReputationScore:    75.0,
		DownloadCount:      5000,
		Age:                200,
		IsFromOfficialRepo: true,
		Metadata:           map[string]interface{}{},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score package: %v", err)
	}

	if score.Confidence < 0 || score.Confidence > 1 {
		t.Errorf("confidence out of range: %f", score.Confidence)
	}
}

func TestClearScores(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "clear-pkg",
		Version:            "1.0.0",
		IsSigned:           true,
		ReputationScore:    80.0,
		DownloadCount:      1000,
		Age:                100,
		IsFromOfficialRepo: true,
		Metadata:           map[string]interface{}{},
	}

	engine.ScorePackage(input)

	engine.ClearScores()

	stats := engine.GetStatistics()
	if stats["total_scores"] != 0 {
		t.Errorf("expected 0 total scores after clear, got %v", stats["total_scores"])
	}
}

func TestConcurrentScoring(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(index int) {
			input := scoring.RiskFactorInput{
				PackageName:        fmt.Sprintf("concurrent-pkg%d", index),
				Version:            "1.0.0",
				IsSigned:           index%2 == 0,
				ReputationScore:    float64(50 + index*5),
				DownloadCount:      int64(1000 * index),
				Age:                100,
				IsFromOfficialRepo: true,
				Metadata:           map[string]interface{}{},
			}
			engine.ScorePackage(input)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	stats := engine.GetStatistics()
	if stats["total_scores"] != 10 {
		t.Errorf("expected 10 scores from concurrent operations, got %v", stats["total_scores"])
	}
}

func TestDeprecatedPackageScoring(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "deprecated-pkg",
		Version:            "1.0.0",
		IsMaintained:       false,
		IsSigned:           true,
		ReputationScore:    60.0,
		DownloadCount:      100,
		Age:                1000,
		IsFromOfficialRepo: true,
		Metadata:           map[string]interface{}{},
	}

	score, err := engine.ScorePackage(input)
	if err != nil {
		t.Fatalf("failed to score deprecated package: %v", err)
	}

	if score.Factors[scoring.RiskFactorDeprecatedPackage] == 0 {
		t.Error("deprecated package factor not calculated")
	}
}

// Benchmarks

func BenchmarkScorePackage(b *testing.B) {
	engine := scoring.NewThreatScoringEngine()

	input := scoring.RiskFactorInput{
		PackageName:        "bench-pkg",
		Version:            "1.0.0",
		IsSigned:           true,
		ReputationScore:    75.0,
		DownloadCount:      1000,
		Age:                100,
		IsFromOfficialRepo: true,
		Metadata:           map[string]interface{}{},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		input.PackageName = fmt.Sprintf("bench-pkg%d", i)
		engine.ScorePackage(input)
	}
}

func BenchmarkGetStatistics(b *testing.B) {
	engine := scoring.NewThreatScoringEngine()

	for i := 0; i < 100; i++ {
		input := scoring.RiskFactorInput{
			PackageName:        fmt.Sprintf("stat-pkg%d", i),
			Version:            "1.0.0",
			IsSigned:           true,
			ReputationScore:    75.0,
			DownloadCount:      1000,
			Age:                100,
			IsFromOfficialRepo: true,
			Metadata:           map[string]interface{}{},
		}
		engine.ScorePackage(input)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.GetStatistics()
	}
}

func BenchmarkGetHighestRiskScores(b *testing.B) {
	engine := scoring.NewThreatScoringEngine()

	for i := 0; i < 50; i++ {
		input := scoring.RiskFactorInput{
			PackageName:        fmt.Sprintf("risk-pkg%d", i),
			Version:            "1.0.0",
			ReputationScore:    float64((i*7)%100 + 20),
			IsSigned:           i%2 == 0,
			DownloadCount:      int64(100 * (i + 1)),
			Age:                100,
			IsFromOfficialRepo: true,
			Metadata:           map[string]interface{}{},
		}
		engine.ScorePackage(input)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.GetHighestRiskScores(10)
	}
}

func BenchmarkUpdateWeights(b *testing.B) {
	engine := scoring.NewThreatScoringEngine()

	newWeights := map[scoring.RiskFactor]float64{
		scoring.RiskFactorTyposquatting:     0.20,
		scoring.RiskFactorCVEAssociated:     0.18,
		scoring.RiskFactorReputationLow:     0.17,
		scoring.RiskFactorDownloadAnomalies: 0.15,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.UpdateWeights(newWeights)
	}
}
