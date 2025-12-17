package anomaly

import (
	"fmt"
	"math"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Nash0810/TraceOrigin/pkg/correlator"
	"github.com/Nash0810/TraceOrigin/pkg/manifest"
)

// AnomalyDetector identifies suspicious patterns in package downloads and installations
type AnomalyDetector struct {
	chains              []*correlator.DependencyChain
	declaredPackages    map[string]*manifest.DeclaredPackage
	anomalies           []*Anomaly
	threatScores        map[string]float64
	baselinePatterns    *BaselinePatterns
	behavioralProfiles  map[string]*BehavioralProfile
}

// Anomaly represents a detected anomaly with context
type Anomaly struct {
	PackageName      string    `json:"package_name"`
	AnomalyType      string    `json:"anomaly_type"` // behavioral, statistical, pattern, behavioral_deviation
	Severity         string    `json:"severity"`      // low, medium, high, critical
	Confidence       float64   `json:"confidence"`    // 0.0 to 1.0
	Description      string    `json:"description"`
	Evidence         []string  `json:"evidence"`      // Supporting evidence
	Indicators       []string  `json:"indicators"`    // Specific indicators
	ThreatScore      float64   `json:"threat_score"` // 0.0 to 100.0
	Timestamp        time.Time `json:"timestamp"`
	Remediation      string    `json:"remediation"`   // Suggested action
	RelatedPackages  []string  `json:"related_packages,omitempty"`
}

// BaselinePatterns represents normal download patterns
type BaselinePatterns struct {
	AverageDownloadSize      int64                 `json:"avg_download_size"`
	AverageDownloadTime      int64                 `json:"avg_download_time"` // milliseconds
	CommonDownloadDomains    map[string]int        `json:"common_domains"`
	TypicalDependencyDepth   int                   `json:"typical_dependency_depth"`
	CommonPackageVersions    map[string][]string   `json:"common_versions"`
	EstimatedThreatLevel     string                `json:"estimated_threat_level"`
	LastUpdated              time.Time             `json:"last_updated"`
}

// BehavioralProfile represents package-specific behavior patterns
type BehavioralProfile struct {
	PackageName              string            `json:"package_name"`
	NormalDownloadSize       int64             `json:"normal_download_size"`
	NormalDownloadDomains    []string          `json:"normal_domains"`
	TrustedRegistries        map[string]bool   `json:"trusted_registries"`
	VersionHistory           []string          `json:"version_history"`
	DependencyGraph          map[string]int    `json:"dependency_graph"`
	AnomalyCount             int               `json:"anomaly_count"`
	LastSeen                 time.Time         `json:"last_seen"`
	RiskLevel                string            `json:"risk_level"`
}

// BehavioralDeviation represents deviation from expected behavior
type BehavioralDeviation struct {
	Package              string  `json:"package"`
	DeviationType        string  `json:"deviation_type"` // size, timing, domain, dependency, frequency
	ExpectedValue        string  `json:"expected_value"`
	ObservedValue        string  `json:"observed_value"`
	DeviationPercentage  float64 `json:"deviation_percentage"`
	IsAnomalous          bool    `json:"is_anomalous"`
	ZScore               float64 `json:"z_score"` // For statistical analysis
}

// StatisticalMetrics for anomaly detection
type StatisticalMetrics struct {
	Mean              float64
	StdDev            float64
	Median            float64
	Q1                float64
	Q3                float64
	IQR               float64
	OutlierThreshold  float64
}

// NewAnomalyDetector creates a new anomaly detection engine
func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		chains:             make([]*correlator.DependencyChain, 0),
		declaredPackages:   make(map[string]*manifest.DeclaredPackage),
		anomalies:          make([]*Anomaly, 0),
		threatScores:       make(map[string]float64),
		behavioralProfiles: make(map[string]*BehavioralProfile),
		baselinePatterns: &BaselinePatterns{
			CommonDownloadDomains: make(map[string]int),
			CommonPackageVersions: make(map[string][]string),
			LastUpdated:           time.Now(),
		},
	}
}

// AddChain adds a dependency chain for analysis
func (ad *AnomalyDetector) AddChain(chain *correlator.DependencyChain) {
	ad.chains = append(ad.chains, chain)
}

// AddDeclaredPackage adds declared package information
func (ad *AnomalyDetector) AddDeclaredPackage(pkg *manifest.DeclaredPackage) {
	ad.declaredPackages[pkg.Name] = pkg
}

// DetectAnomalies performs comprehensive anomaly detection
func (ad *AnomalyDetector) DetectAnomalies() []*Anomaly {
	ad.anomalies = make([]*Anomaly, 0)

	// Run multiple detection algorithms
	ad.detectBehavioralAnomalies()
	ad.detectStatisticalAnomalies()
	ad.detectPatternAnomalies()
	ad.detectBehavioralDeviations()
	ad.detectFrequencyAnomalies()
	ad.calculateThreatScores()

	// Sort by threat score
	sort.Slice(ad.anomalies, func(i, j int) bool {
		return ad.anomalies[i].ThreatScore > ad.anomalies[j].ThreatScore
	})

	return ad.anomalies
}

// detectBehavioralAnomalies detects deviations from normal behavior
func (ad *AnomalyDetector) detectBehavioralAnomalies() {
	for _, chain := range ad.chains {
		profile := ad.getOrCreateProfile(chain.PackageName)

		// Check download source
		if ad.isUnusualDownloadSource(chain.PackageName, chain.DownloadURL) {
			anomaly := &Anomaly{
				PackageName:  chain.PackageName,
				AnomalyType:  "behavioral",
				Severity:     "high",
				Confidence:   0.85,
				Description:  "Package downloaded from unusual registry domain",
				Indicators:   []string{"unusual_domain", "non_standard_registry"},
				ThreatScore:  75.0,
				Timestamp:    time.Now(),
				Remediation:  "Verify registry authenticity and package integrity",
			}

			// Add evidence
			if chain.DownloadURL != "" {
				domain := extractDomain(chain.DownloadURL)
				anomaly.Evidence = append(anomaly.Evidence,
					fmt.Sprintf("Download domain: %s", domain),
					fmt.Sprintf("Expected: %v", profile.NormalDownloadDomains),
				)
			}

			ad.anomalies = append(ad.anomalies, anomaly)
		}

		// Check version pattern
		if ad.isUnusualVersionPattern(chain.PackageName, chain.ActualVersion) {
			anomaly := &Anomaly{
				PackageName:  chain.PackageName,
				AnomalyType:  "behavioral",
				Severity:     "medium",
				Confidence:   0.75,
				Description:  "Unusual version pattern detected",
				Indicators:   []string{"prerelease_version", "unusual_version_format"},
				ThreatScore:  55.0,
				Timestamp:    time.Now(),
				Remediation:  "Review version constraints and stability requirements",
			}
			anomaly.Evidence = append(anomaly.Evidence,
				fmt.Sprintf("Version: %s", chain.ActualVersion),
				fmt.Sprintf("Previous versions: %v", profile.VersionHistory),
			)
			ad.anomalies = append(ad.anomalies, anomaly)
		}
	}
}

// detectStatisticalAnomalies uses statistical methods
func (ad *AnomalyDetector) detectStatisticalAnomalies() {
	// Collect URL lengths as proxy for download size
	urlLengths := make(map[string][]int64)
	for _, chain := range ad.chains {
		urlLengths[chain.PackageName] = append(urlLengths[chain.PackageName], int64(len(chain.DownloadURL)))
	}

	// Analyze each package
	for pkgName, lengths := range urlLengths {
		if len(lengths) < 2 {
			continue
		}

		metrics := calculateStatistics(lengths)

		for _, length := range lengths {
			zScore := (float64(length) - metrics.Mean) / metrics.StdDev
			if math.Abs(zScore) > 3.0 { // 3-sigma rule
				anomaly := &Anomaly{
					PackageName:  pkgName,
					AnomalyType:  "statistical",
					Severity:     "medium",
					Confidence:   0.80,
					Description:  "URL pattern is statistical outlier (3-sigma)",
					Indicators:   []string{"unusual_url_pattern", "url_outlier"},
					ThreatScore:  60.0,
					Timestamp:    time.Now(),
					Remediation:  "Verify package integrity through hash verification",
				}
				anomaly.Evidence = append(anomaly.Evidence,
					fmt.Sprintf("URL length: %d bytes", length),
					fmt.Sprintf("Average length: %.0f bytes", metrics.Mean),
					fmt.Sprintf("Z-score: %.2f", zScore),
				)
				ad.anomalies = append(ad.anomalies, anomaly)
			}
		}
	}
}

// detectPatternAnomalies detects suspicious patterns
func (ad *AnomalyDetector) detectPatternAnomalies() {
	// Define typosquatting pairs
	typosquattingPairs := map[string]string{
		"flask": "flak",
		"django": "djan",
		"requests": "requst",
		"numpy": "numpay",
		"pandas": "panda",
	}

	patterns := map[string]*regexp.Regexp{
		"obfuscation_pattern": regexp.MustCompile(`(?i)[a-z0-9]{20,}\.whl`),
		"suspicious_encoding": regexp.MustCompile(`(?i)(%[0-9a-f]{2}|&#[0-9]{1,5})`),
	}

	for _, chain := range ad.chains {
		// Check for typosquatting
		for legitimate, typo := range typosquattingPairs {
			if chain.PackageName == typo || strings.Contains(strings.ToLower(chain.PackageName), typo) {
				anomaly := &Anomaly{
					PackageName: chain.PackageName,
					AnomalyType: "pattern",
					Severity:    "critical",
					Confidence:  0.95,
					Description: fmt.Sprintf("Typosquatting detected: %s looks like %s", chain.PackageName, legitimate),
					Indicators:  []string{"typosquatting_pattern"},
					ThreatScore: 95.0,
					Timestamp:   time.Now(),
					Remediation: "Investigate package origin and remove from production immediately",
				}
				ad.anomalies = append(ad.anomalies, anomaly)
			}
		}

		// Check other patterns
		for patternName, pattern := range patterns {
			if pattern.MatchString(chain.PackageName) || pattern.MatchString(chain.DownloadURL) {
				severity := "high"

				anomaly := &Anomaly{
					PackageName: chain.PackageName,
					AnomalyType: "pattern",
					Severity:    severity,
					Confidence:  0.90,
					Description: fmt.Sprintf("Suspicious pattern detected: %s", patternName),
					Indicators:  []string{patternName},
					ThreatScore: 80.0,
					Timestamp:   time.Now(),
					Remediation: "Investigate package origin and remove from production immediately",
				}

				ad.anomalies = append(ad.anomalies, anomaly)
			}
		}
	}
}

// detectBehavioralDeviations detects deviations from baseline
func (ad *AnomalyDetector) detectBehavioralDeviations() {
	for _, chain := range ad.chains {
		// Check if package behaves differently than expected
		declaredPkg := ad.declaredPackages[chain.PackageName]
		if declaredPkg == nil {
			continue
		}

		// Detect version deviation
		if chain.ActualVersion != declaredPkg.Version {
			anomaly := &Anomaly{
				PackageName:  chain.PackageName,
				AnomalyType:  "behavioral_deviation",
				Severity:     "high",
				Confidence:   0.95,
				Description:  fmt.Sprintf("Version deviation: declared %s, observed %s", declaredPkg.Version, chain.ActualVersion),
				Indicators:   []string{"version_mismatch", "unexpected_version"},
				ThreatScore:  75.0,
				Timestamp:    time.Now(),
				Remediation:  "Review and update manifest constraints",
			}

			if compareVersions(chain.ActualVersion, declaredPkg.Version) < 0 {
				anomaly.Severity = "critical"
				anomaly.ThreatScore = 90.0
				anomaly.Description = fmt.Sprintf("CRITICAL: Downgrade detected - %s to %s", declaredPkg.Version, chain.ActualVersion)
			}

			ad.anomalies = append(ad.anomalies, anomaly)
		}
	}
}

// detectFrequencyAnomalies detects unusual access patterns
func (ad *AnomalyDetector) detectFrequencyAnomalies() {
	packageFrequency := make(map[string]int)
	packageDomainFrequency := make(map[string]map[string]int)

	for _, chain := range ad.chains {
		packageFrequency[chain.PackageName]++
		if packageDomainFrequency[chain.PackageName] == nil {
			packageDomainFrequency[chain.PackageName] = make(map[string]int)
		}
		domain := extractDomain(chain.DownloadURL)
		packageDomainFrequency[chain.PackageName][domain]++
	}

	// Detect high-frequency suspicious patterns
	for pkgName, freq := range packageFrequency {
		if freq > 5 {
			// Multiple downloads of same package = suspicious
			anomaly := &Anomaly{
				PackageName: pkgName,
				AnomalyType: "behavioral",
				Severity:    "medium",
				Confidence:  0.70,
				Description: fmt.Sprintf("Unusually high download frequency: %d times", freq),
				Indicators:  []string{"high_frequency", "repeated_downloads"},
				ThreatScore: 50.0,
				Timestamp:   time.Now(),
				Remediation: "Investigate dependency resolution and caching",
			}
			ad.anomalies = append(ad.anomalies, anomaly)
		}

		// Detect domain switching
		if len(packageDomainFrequency[pkgName]) > 2 {
			anomaly := &Anomaly{
				PackageName: pkgName,
				AnomalyType: "behavioral",
				Severity:    "high",
				Confidence:  0.85,
				Description: "Package downloaded from multiple registry domains",
				Indicators:  []string{"domain_switching", "multiple_registries"},
				ThreatScore: 70.0,
				Timestamp:   time.Now(),
				Remediation: "Standardize registry configuration",
			}

			for domain := range packageDomainFrequency[pkgName] {
				anomaly.Evidence = append(anomaly.Evidence, fmt.Sprintf("Domain: %s", domain))
			}

			ad.anomalies = append(ad.anomalies, anomaly)
		}
	}
}

// calculateThreatScores computes composite threat scores
func (ad *AnomalyDetector) calculateThreatScores() {
	for _, anomaly := range ad.anomalies {
		// Base score from anomaly
		score := anomaly.ThreatScore

		// Adjust by confidence
		score *= anomaly.Confidence

		// Adjust by severity
		severityMultiplier := map[string]float64{
			"low":      0.5,
			"medium":   1.0,
			"high":     1.5,
			"critical": 2.0,
		}
		if multiplier, ok := severityMultiplier[anomaly.Severity]; ok {
			score *= multiplier
		}

		// Cap at 100
		if score > 100.0 {
			score = 100.0
		}

		anomaly.ThreatScore = score
		ad.threatScores[anomaly.PackageName] = score
	}
}

// GetAnomaliesBySeverity returns anomalies filtered by severity
func (ad *AnomalyDetector) GetAnomaliesBySeverity(severity string) []*Anomaly {
	result := make([]*Anomaly, 0)
	for _, anomaly := range ad.anomalies {
		if anomaly.Severity == severity {
			result = append(result, anomaly)
		}
	}
	return result
}

// GetAnomaliesByPackage returns anomalies for a specific package
func (ad *AnomalyDetector) GetAnomaliesByPackage(packageName string) []*Anomaly {
	result := make([]*Anomaly, 0)
	for _, anomaly := range ad.anomalies {
		if anomaly.PackageName == packageName {
			result = append(result, anomaly)
		}
	}
	return result
}

// GetThreatScore returns the threat score for a package
func (ad *AnomalyDetector) GetThreatScore(packageName string) float64 {
	if score, ok := ad.threatScores[packageName]; ok {
		return score
	}
	return 0.0
}

// GetAverageRiskLevel returns overall risk assessment
func (ad *AnomalyDetector) GetAverageRiskLevel() string {
	if len(ad.threatScores) == 0 {
		return "low"
	}

	totalScore := 0.0
	for _, score := range ad.threatScores {
		totalScore += score
	}
	avgScore := totalScore / float64(len(ad.threatScores))

	if avgScore >= 80 {
		return "critical"
	} else if avgScore >= 60 {
		return "high"
	} else if avgScore >= 40 {
		return "medium"
	}
	return "low"
}

// Helper functions

func (ad *AnomalyDetector) isUnusualDownloadSource(pkgName, url string) bool {
	// List of trusted registries
	trustedDomains := map[string]bool{
		"files.pythonhosted.org":        true,
		"registry.npmjs.org":            true,
		"proxy.golang.org":              true,
		"rubygems.org":                  true,
		"crates.io":                     true,
		"archive.ubuntu.com":            true,
		"security.ubuntu.com":           true,
	}

	domain := extractDomain(url)
	return !trustedDomains[domain] && domain != ""
}

func (ad *AnomalyDetector) isUnusualVersionPattern(pkgName, version string) bool {
	// Check for prerelease markers
	preReleaseMarkers := []string{"alpha", "beta", "rc", "dev", "a", "b"}
	for _, marker := range preReleaseMarkers {
		if strings.Contains(strings.ToLower(version), marker) {
			return true
		}
	}
	return false
}

func (ad *AnomalyDetector) getOrCreateProfile(pkgName string) *BehavioralProfile {
	if profile, ok := ad.behavioralProfiles[pkgName]; ok {
		return profile
	}

	profile := &BehavioralProfile{
		PackageName:        pkgName,
		TrustedRegistries:  make(map[string]bool),
		DependencyGraph:    make(map[string]int),
		NormalDownloadDomains: []string{},
		VersionHistory:     []string{},
		LastSeen:           time.Now(),
		RiskLevel:          "unknown",
	}

	ad.behavioralProfiles[pkgName] = profile
	return profile
}

func extractDomain(url string) string {
	if url == "" {
		return ""
	}

	// Extract domain from URL
	parts := strings.Split(url, "/")
	for _, part := range parts {
		if strings.Contains(part, ".") && !strings.Contains(part, ":") {
			return part
		}
	}
	return ""
}

func calculateStatistics(values []int64) StatisticalMetrics {
	if len(values) == 0 {
		return StatisticalMetrics{}
	}

	// Calculate mean
	sum := int64(0)
	for _, v := range values {
		sum += v
	}
	mean := float64(sum) / float64(len(values))

	// Calculate standard deviation
	variance := 0.0
	for _, v := range values {
		diff := float64(v) - mean
		variance += diff * diff
	}
	variance /= float64(len(values))
	stdDev := math.Sqrt(variance)

	// Calculate median
	sorted := make([]int64, len(values))
	copy(sorted, values)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	median := float64(sorted[len(sorted)/2])
	if len(sorted)%2 == 0 {
		median = (float64(sorted[len(sorted)/2-1]) + float64(sorted[len(sorted)/2])) / 2
	}

	// Calculate quartiles
	q1Index := len(sorted) / 4
	q3Index := (3 * len(sorted)) / 4
	q1 := float64(sorted[q1Index])
	q3 := float64(sorted[q3Index])

	return StatisticalMetrics{
		Mean:             mean,
		StdDev:           stdDev,
		Median:           median,
		Q1:               q1,
		Q3:               q3,
		IQR:              q3 - q1,
		OutlierThreshold: q3 + (1.5 * (q3 - q1)),
	}
}

func compareVersions(v1, v2 string) int {
	// Simple version comparison (returns -1 if v1 < v2, 0 if equal, 1 if v1 > v2)
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	for i := 0; i < len(parts1) && i < len(parts2); i++ {
		n1 := parseInt(parts1[i])
		n2 := parseInt(parts2[i])

		if n1 < n2 {
			return -1
		} else if n1 > n2 {
			return 1
		}
	}

	if len(parts1) < len(parts2) {
		return -1
	} else if len(parts1) > len(parts2) {
		return 1
	}
	return 0
}

func parseInt(s string) int {
	// Extract number from version part
	result := 0
	for _, ch := range s {
		if ch >= '0' && ch <= '9' {
			result = result*10 + int(ch-'0')
		} else {
			break
		}
	}
	return result
}

// GetSummary returns a summary of anomalies detected
func (ad *AnomalyDetector) GetSummary() map[string]interface{} {
	summaryBySeverity := make(map[string]int)
	summaryByType := make(map[string]int)

	for _, anomaly := range ad.anomalies {
		summaryBySeverity[anomaly.Severity]++
		summaryByType[anomaly.AnomalyType]++
	}

	return map[string]interface{}{
		"total_anomalies":      len(ad.anomalies),
		"by_severity":          summaryBySeverity,
		"by_type":              summaryByType,
		"average_risk_level":   ad.GetAverageRiskLevel(),
		"packages_with_issues": len(ad.threatScores),
		"timestamp":            time.Now(),
	}
}
