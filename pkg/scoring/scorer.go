package scoring

import (
	"fmt"
	"math"
	"sort"
	"sync"
	"time"
)

// ThreatLevel defines the severity of a threat
type ThreatLevel string

const (
	ThreatLevelCritical ThreatLevel = "critical"
	ThreatLevelHigh     ThreatLevel = "high"
	ThreatLevelMedium   ThreatLevel = "medium"
	ThreatLevelLow      ThreatLevel = "low"
	ThreatLevelInfo     ThreatLevel = "info"
)

// RiskFactor represents a factor contributing to threat score
type RiskFactor string

const (
	RiskFactorTyposquatting      RiskFactor = "typosquatting"
	RiskFactorUnexpectedDomain   RiskFactor = "unexpected_domain"
	RiskFactorVersionMismatch    RiskFactor = "version_mismatch"
	RiskFactorUnsignedPackage    RiskFactor = "unsigned_package"
	RiskFactorReputationLow      RiskFactor = "low_reputation"
	RiskFactorDownloadAnomalies  RiskFactor = "download_anomalies"
	RiskFactorNewPackage         RiskFactor = "new_package"
	RiskFactorDeprecatedPackage  RiskFactor = "deprecated_package"
	RiskFactorSuspiciousMetadata RiskFactor = "suspicious_metadata"
	RiskFactorCVEAssociated      RiskFactor = "cve_associated"
	RiskFactorNonStandardRepo    RiskFactor = "non_standard_repo"
	RiskFactorHighEntropy        RiskFactor = "high_entropy_activity"
)

// ThreatScore represents a calculated threat score
type ThreatScore struct {
	PackageName      string
	Version          string
	Score            float64                     // 0-100
	ThreatLevel      ThreatLevel
	Factors          map[RiskFactor]float64
	RiskDescription  string
	DetectedAt       time.Time
	Recommendations  []string
	Metadata         map[string]interface{}
	Confidence       float64 // 0-1
	IsAnomalous      bool
	PreviousScores   []float64
	TrendDirection   string // "increasing", "decreasing", "stable"
}

// ThreatScoringEngine calculates threat scores for packages
type ThreatScoringEngine struct {
	scores              map[string]*ThreatScore
	factorWeights       map[RiskFactor]float64
	baselineData        *BaselineData
	anomalyDetector     *AnomalyDetector
	mu                  sync.RWMutex
	idCounter           int64
	historyLength       int
	scoringHistory      map[string][]*ThreatScore
	weightingAlgorithm  WeightingAlgorithm
	modelUpdateTime     time.Time
	modelVersion        string
}

// BaselineData contains baseline statistics for normal packages
type BaselineData struct {
	AverageDownloads    float64
	AverageSize         int64
	AverageAge          int
	CommonMaintainers   []string
	TrustedDomains      map[string][]string
	VerifiedPublishers  map[string]bool
	KnownMalicious      map[string]bool
	UpdatedAt           time.Time
}

// AnomalyDetector detects unusual patterns
type AnomalyDetector struct {
	mean             float64
	stdDev           float64
	zScoreThreshold  float64
	observations     []float64
	maxObservations  int
}

// WeightingAlgorithm defines how factors are weighted
type WeightingAlgorithm string

const (
	WeightingLinear    WeightingAlgorithm = "linear"
	WeightingExponential WeightingAlgorithm = "exponential"
	WeightingML        WeightingAlgorithm = "ml"
)

// RiskFactorInput contains inputs for scoring
type RiskFactorInput struct {
	PackageName          string
	Version              string
	DownloadDomain       string
	IsTyposquatting      bool
	TyposquattingScore   float64 // 0-1
	VersionMismatch      bool
	IsSigned             bool
	ReputationScore      float64 // 0-100
	DownloadCount        int64
	Age                  int // days since first release
	IsMaintained         bool
	AssociatedCVEs       []string
	DownloadSourceCount  int
	IsFromOfficialRepo   bool
	Metadata             map[string]interface{}
}

// NewThreatScoringEngine creates a new threat scoring engine
func NewThreatScoringEngine() *ThreatScoringEngine {
	return &ThreatScoringEngine{
		scores:         make(map[string]*ThreatScore),
		factorWeights:  getDefaultWeights(),
		baselineData:   &BaselineData{TrustedDomains: make(map[string][]string), VerifiedPublishers: make(map[string]bool), KnownMalicious: make(map[string]bool)},
		anomalyDetector: &AnomalyDetector{zScoreThreshold: 3.0, observations: make([]float64, 0), maxObservations: 1000},
		historyLength:  100,
		scoringHistory: make(map[string][]*ThreatScore),
		weightingAlgorithm: WeightingLinear,
		modelVersion:   "1.0",
		modelUpdateTime: time.Now(),
	}
}

// ScorePackage calculates threat score for a package
func (tse *ThreatScoringEngine) ScorePackage(input RiskFactorInput) (*ThreatScore, error) {
	tse.mu.Lock()
	defer tse.mu.Unlock()

	if input.PackageName == "" {
		return nil, fmt.Errorf("package name is required")
	}

	score := &ThreatScore{
		PackageName:     input.PackageName,
		Version:         input.Version,
		Factors:         make(map[RiskFactor]float64),
		DetectedAt:      time.Now(),
		Recommendations: make([]string, 0),
		Metadata:        input.Metadata,
	}

	// Calculate individual risk factors
	tse.calculateTyposquattingFactor(score, input)
	tse.calculateVersionMismatchFactor(score, input)
	tse.calculateSignatureFactor(score, input)
	tse.calculateReputationFactor(score, input)
	tse.calculateDownloadAnomalyFactor(score, input)
	tse.calculateNewPackageFactor(score, input)
	tse.calculateMaintenanceFactor(score, input)
	tse.calculateCVEFactor(score, input)
	tse.calculateRepoSourceFactor(score, input)

	// Calculate composite score
	tse.calculateCompositeScore(score)

	// Determine threat level
	score.ThreatLevel = tse.threatLevelFromScore(score.Score)

	// Generate recommendations
	tse.generateRecommendations(score)

	// Check for anomalies
	score.IsAnomalous = tse.isAnomalous(score.Score)

	// Track confidence
	score.Confidence = tse.calculateConfidence(score)

	// Update trend
	tse.updateTrendData(score)

	// Store score
	key := fmt.Sprintf("%s:%s", input.PackageName, input.Version)
	tse.scores[key] = score

	// Store in history
	if _, exists := tse.scoringHistory[input.PackageName]; !exists {
		tse.scoringHistory[input.PackageName] = make([]*ThreatScore, 0)
	}
	tse.scoringHistory[input.PackageName] = append(tse.scoringHistory[input.PackageName], score)
	if len(tse.scoringHistory[input.PackageName]) > tse.historyLength {
		tse.scoringHistory[input.PackageName] = tse.scoringHistory[input.PackageName][1:]
	}

	return score, nil
}

// calculateTyposquattingFactor scores similarity to known packages
func (tse *ThreatScoringEngine) calculateTyposquattingFactor(score *ThreatScore, input RiskFactorInput) {
	factor := 0.0
	if input.IsTyposquatting {
		factor = 40.0 + (input.TyposquattingScore * 40.0)
	}
	score.Factors[RiskFactorTyposquatting] = factor
}

// calculateVersionMismatchFactor scores version inconsistencies
func (tse *ThreatScoringEngine) calculateVersionMismatchFactor(score *ThreatScore, input RiskFactorInput) {
	factor := 0.0
	if input.VersionMismatch {
		factor = 25.0
	}
	score.Factors[RiskFactorVersionMismatch] = factor
}

// calculateSignatureFactor scores package signing status
func (tse *ThreatScoringEngine) calculateSignatureFactor(score *ThreatScore, input RiskFactorInput) {
	factor := 0.0
	if !input.IsSigned {
		factor = 15.0
	}
	score.Factors[RiskFactorUnsignedPackage] = factor
}

// calculateReputationFactor scores package reputation
func (tse *ThreatScoringEngine) calculateReputationFactor(score *ThreatScore, input RiskFactorInput) {
	factor := 0.0
	// Low reputation (0-30) is high risk
	if input.ReputationScore < 30 {
		factor = 30.0 - (input.ReputationScore * 0.5)
	}
	score.Factors[RiskFactorReputationLow] = factor
}

// calculateDownloadAnomalyFactor scores download patterns
func (tse *ThreatScoringEngine) calculateDownloadAnomalyFactor(score *ThreatScore, input RiskFactorInput) {
	factor := 0.0
	// Multiple download sources is anomalous
	if input.DownloadSourceCount > 3 {
		factor = 20.0 + math.Min(10.0, float64(input.DownloadSourceCount-3)*2.0)
	}
	// Very low download count is suspicious
	if input.DownloadCount < 10 && input.Age > 30 {
		factor = math.Max(factor, 15.0)
	}
	score.Factors[RiskFactorDownloadAnomalies] = factor
}

// calculateNewPackageFactor scores newly created packages
func (tse *ThreatScoringEngine) calculateNewPackageFactor(score *ThreatScore, input RiskFactorInput) {
	factor := 0.0
	// Very new packages (< 7 days) with high downloads are suspicious
	if input.Age < 7 && input.DownloadCount > 100 {
		factor = 20.0
	}
	// Packages < 30 days are somewhat risky
	if input.Age < 30 && input.DownloadCount > 1000 {
		factor = 10.0
	}
	score.Factors[RiskFactorNewPackage] = factor
}

// calculateMaintenanceFactor scores maintenance status
func (tse *ThreatScoringEngine) calculateMaintenanceFactor(score *ThreatScore, input RiskFactorInput) {
	factor := 0.0
	if !input.IsMaintained {
		factor = 10.0
	}
	score.Factors[RiskFactorDeprecatedPackage] = factor
}

// calculateCVEFactor scores CVE associations
func (tse *ThreatScoringEngine) calculateCVEFactor(score *ThreatScore, input RiskFactorInput) {
	factor := 0.0
	if len(input.AssociatedCVEs) > 0 {
		// Each CVE adds 15 points, capped at 40
		factor = math.Min(40.0, float64(len(input.AssociatedCVEs))*15.0)
	}
	score.Factors[RiskFactorCVEAssociated] = factor
}

// calculateRepoSourceFactor scores repository source
func (tse *ThreatScoringEngine) calculateRepoSourceFactor(score *ThreatScore, input RiskFactorInput) {
	factor := 0.0
	if !input.IsFromOfficialRepo {
		factor = 20.0
	}
	score.Factors[RiskFactorNonStandardRepo] = factor
}

// calculateCompositeScore combines all factors
func (tse *ThreatScoringEngine) calculateCompositeScore(score *ThreatScore) {
	total := 0.0
	weightSum := 0.0

	for factor, value := range score.Factors {
		weight := tse.factorWeights[factor]
		total += value * weight
		weightSum += weight
	}

	if weightSum > 0 {
		score.Score = total / weightSum
	}

	// Normalize to 0-100
	score.Score = math.Min(100.0, math.Max(0.0, score.Score))
}

// threatLevelFromScore converts score to threat level
func (tse *ThreatScoringEngine) threatLevelFromScore(score float64) ThreatLevel {
	switch {
	case score >= 80:
		return ThreatLevelCritical
	case score >= 60:
		return ThreatLevelHigh
	case score >= 40:
		return ThreatLevelMedium
	case score >= 20:
		return ThreatLevelLow
	default:
		return ThreatLevelInfo
	}
}

// generateRecommendations creates actionable recommendations
func (tse *ThreatScoringEngine) generateRecommendations(score *ThreatScore) {
	score.Recommendations = make([]string, 0)

	if score.Factors[RiskFactorTyposquatting] > 30 {
		score.Recommendations = append(score.Recommendations, "verify package name spelling in manifest")
	}

	if score.Factors[RiskFactorUnsignedPackage] > 5 {
		score.Recommendations = append(score.Recommendations, "verify package signature with publisher")
	}

	if score.Factors[RiskFactorReputationLow] > 15 {
		score.Recommendations = append(score.Recommendations, "research package maintainer and community reviews")
	}

	if score.Factors[RiskFactorDownloadAnomalies] > 15 {
		score.Recommendations = append(score.Recommendations, "investigate unusual download patterns")
	}

	if score.Factors[RiskFactorNewPackage] > 15 {
		score.Recommendations = append(score.Recommendations, "exercise caution with newly released packages")
	}

	if score.Factors[RiskFactorCVEAssociated] > 0 {
		score.Recommendations = append(score.Recommendations, "update to patched version or use alternative")
	}

	if score.Factors[RiskFactorNonStandardRepo] > 5 {
		score.Recommendations = append(score.Recommendations, "switch to official package repository")
	}

	if score.ThreatLevel == ThreatLevelCritical {
		score.Recommendations = append(score.Recommendations, "DO NOT USE in production - replace with verified alternative")
	} else if score.ThreatLevel == ThreatLevelHigh {
		score.Recommendations = append(score.Recommendations, "use with caution - implement additional monitoring")
	}
}

// isAnomalous detects anomalous scores
func (tse *ThreatScoringEngine) isAnomalous(score float64) bool {
	if len(tse.anomalyDetector.observations) < 10 {
		return false
	}

	zScore := (score - tse.anomalyDetector.mean) / tse.anomalyDetector.stdDev
	return math.Abs(zScore) > tse.anomalyDetector.zScoreThreshold
}

// calculateConfidence estimates scoring confidence
func (tse *ThreatScoringEngine) calculateConfidence(score *ThreatScore) float64 {
	confidence := 0.5
	factorCount := len(score.Factors)
	confidence += float64(factorCount) * 0.03

	// More extreme scores are less confident (more likely to be false positives)
	if score.Score < 20 || score.Score > 80 {
		confidence -= 0.1
	}

	return math.Min(1.0, math.Max(0.0, confidence))
}

// updateTrendData analyzes score trends
func (tse *ThreatScoringEngine) updateTrendData(score *ThreatScore) {
	history := tse.scoringHistory[score.PackageName]
	if len(history) < 2 {
		score.TrendDirection = "stable"
		score.PreviousScores = make([]float64, 0)
		return
	}

	score.PreviousScores = make([]float64, 0)
	for _, s := range history[max(0, len(history)-10):] {
		score.PreviousScores = append(score.PreviousScores, s.Score)
	}

	if len(history) >= 2 {
		recent := score.Score
		previous := history[len(history)-2].Score

		if recent > previous+5 {
			score.TrendDirection = "increasing"
		} else if recent < previous-5 {
			score.TrendDirection = "decreasing"
		} else {
			score.TrendDirection = "stable"
		}
	}
}

// GetScore retrieves a threat score
func (tse *ThreatScoringEngine) GetScore(packageName, version string) (*ThreatScore, bool) {
	tse.mu.RLock()
	defer tse.mu.RUnlock()

	key := fmt.Sprintf("%s:%s", packageName, version)
	score, exists := tse.scores[key]
	return score, exists
}

// GetScoreHistory retrieves score history for a package
func (tse *ThreatScoringEngine) GetScoreHistory(packageName string) []*ThreatScore {
	tse.mu.RLock()
	defer tse.mu.RUnlock()

	history := make([]*ThreatScore, 0)
	if h, exists := tse.scoringHistory[packageName]; exists {
		history = append(history, h...)
	}
	return history
}

// GetScoresByThreatLevel filters scores by threat level
func (tse *ThreatScoringEngine) GetScoresByThreatLevel(level ThreatLevel) []*ThreatScore {
	tse.mu.RLock()
	defer tse.mu.RUnlock()

	results := make([]*ThreatScore, 0)
	for _, score := range tse.scores {
		if score.ThreatLevel == level {
			results = append(results, score)
		}
	}
	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})
	return results
}

// GetHighestRiskScores returns top N highest risk scores
func (tse *ThreatScoringEngine) GetHighestRiskScores(limit int) []*ThreatScore {
	tse.mu.RLock()
	defer tse.mu.RUnlock()

	results := make([]*ThreatScore, 0)
	for _, score := range tse.scores {
		results = append(results, score)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Score > results[j].Score
	})

	if len(results) > limit {
		results = results[:limit]
	}
	return results
}

// UpdateWeights modifies factor weights
func (tse *ThreatScoringEngine) UpdateWeights(weights map[RiskFactor]float64) {
	tse.mu.Lock()
	defer tse.mu.Unlock()

	for factor, weight := range weights {
		if weight >= 0 && weight <= 1 {
			tse.factorWeights[factor] = weight
		}
	}
}

// GetWeights returns current factor weights
func (tse *ThreatScoringEngine) GetWeights() map[RiskFactor]float64 {
	tse.mu.RLock()
	defer tse.mu.RUnlock()

	weights := make(map[RiskFactor]float64)
	for k, v := range tse.factorWeights {
		weights[k] = v
	}
	return weights
}

// GetStatistics returns scoring statistics
func (tse *ThreatScoringEngine) GetStatistics() map[string]interface{} {
	tse.mu.RLock()
	defer tse.mu.RUnlock()

	stats := make(map[string]interface{})
	stats["total_scores"] = len(tse.scores)

	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	infoCount := 0

	scores := make([]float64, 0)
	for _, score := range tse.scores {
		scores = append(scores, score.Score)
		switch score.ThreatLevel {
		case ThreatLevelCritical:
			criticalCount++
		case ThreatLevelHigh:
			highCount++
		case ThreatLevelMedium:
			mediumCount++
		case ThreatLevelLow:
			lowCount++
		case ThreatLevelInfo:
			infoCount++
		}
	}

	stats["critical_count"] = criticalCount
	stats["high_count"] = highCount
	stats["medium_count"] = mediumCount
	stats["low_count"] = lowCount
	stats["info_count"] = infoCount

	if len(scores) > 0 {
		sort.Float64s(scores)
		sum := 0.0
		for _, s := range scores {
			sum += s
		}
		stats["average_score"] = sum / float64(len(scores))
		stats["min_score"] = scores[0]
		stats["max_score"] = scores[len(scores)-1]
		stats["median_score"] = scores[len(scores)/2]
	}

	stats["model_version"] = tse.modelVersion
	stats["last_update"] = tse.modelUpdateTime

	return stats
}

// ClearScores removes all scores
func (tse *ThreatScoringEngine) ClearScores() {
	tse.mu.Lock()
	defer tse.mu.Unlock()

	tse.scores = make(map[string]*ThreatScore)
	tse.scoringHistory = make(map[string][]*ThreatScore)
}

// getDefaultWeights returns default factor weights
func getDefaultWeights() map[RiskFactor]float64 {
	return map[RiskFactor]float64{
		RiskFactorTyposquatting:      0.15,
		RiskFactorUnexpectedDomain:   0.12,
		RiskFactorVersionMismatch:    0.10,
		RiskFactorUnsignedPackage:    0.08,
		RiskFactorReputationLow:      0.15,
		RiskFactorDownloadAnomalies:  0.12,
		RiskFactorNewPackage:         0.10,
		RiskFactorDeprecatedPackage:  0.05,
		RiskFactorSuspiciousMetadata: 0.05,
		RiskFactorCVEAssociated:      0.15,
		RiskFactorNonStandardRepo:    0.10,
		RiskFactorHighEntropy:        0.07,
	}
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
