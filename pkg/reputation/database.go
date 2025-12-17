package reputation

import (
	"fmt"
	"sync"
	"time"
)

// PackageReputation represents the reputation of a package
type PackageReputation struct {
	Name              string            `json:"name"`
	PackageManager    string            `json:"package_manager"`
	Version           string            `json:"version,omitempty"`
	ReputationScore   float64           `json:"reputation_score"`   // 0-100, higher is safer
	TrustLevel        string            `json:"trust_level"`        // trusted, neutral, suspicious, malicious
	DownloadCount     int64             `json:"download_count"`
	LastUpdated       time.Time         `json:"last_updated"`
	MalwareRisks      []string          `json:"malware_risks"`
	SecurityIssues    []SecurityIssue   `json:"security_issues"`
	CommunityRating   float64           `json:"community_rating"`   // 0-5 stars
	MaintainerProfile *MaintainerInfo   `json:"maintainer_profile"`
	Dependencies      []DependencyInfo  `json:"dependencies"`
	SourceRepository  string            `json:"source_repository"`
	HasSignedRelease  bool              `json:"has_signed_release"`
	AgeInDays         int               `json:"age_in_days"`
	LastAuditTime     time.Time         `json:"last_audit_time,omitempty"`
	Metadata          map[string]string `json:"metadata"`
}

// SecurityIssue represents a security issue found in a package
type SecurityIssue struct {
	ID          string    `json:"id"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"` // low, medium, high, critical
	Description string    `json:"description"`
	CVE         string    `json:"cve,omitempty"`
	AffectedVersions []string `json:"affected_versions"`
	PublishedDate   time.Time `json:"published_date"`
	FixedVersion    string    `json:"fixed_version,omitempty"`
}

// MaintainerInfo represents information about the package maintainer
type MaintainerInfo struct {
	Name              string    `json:"name"`
	Email             string    `json:"email"`
	GithubProfile     string    `json:"github_profile,omitempty"`
	PackageCount      int       `json:"package_count"`
	FirstPublishDate  time.Time `json:"first_publish_date"`
	LastActiveDate    time.Time `json:"last_active_date"`
	IsOrganization    bool      `json:"is_organization"`
	VerifiedPublisher bool      `json:"verified_publisher"`
	TrustScore        float64   `json:"trust_score"` // 0-100
}

// DependencyInfo represents a dependency of a package
type DependencyInfo struct {
	Name              string  `json:"name"`
	PackageManager    string  `json:"package_manager"`
	Version           string  `json:"version"`
	ReputationScore   float64 `json:"reputation_score"`
	IsOptional        bool    `json:"is_optional"`
	IsDevDependency   bool    `json:"is_dev_dependency"`
}

// ReputationDatabase manages package reputation data
type ReputationDatabase struct {
	packages            map[string]*PackageReputation
	packagesByManager   map[string]map[string]*PackageReputation
	trustedPackages     map[string]bool
	blacklistedPackages map[string]bool
	cacheExpiry         map[string]time.Time
	cacheTTL            time.Duration
	mu                  sync.RWMutex
	lastUpdateTime      time.Time
	updateInterval      time.Duration
}

// TrustLevel constants
const (
	TrustedLevel    = "trusted"
	NeutralLevel    = "neutral"
	SuspiciousLevel = "suspicious"
	MaliciousLevel  = "malicious"
)

// NewReputationDatabase creates a new reputation database
func NewReputationDatabase() *ReputationDatabase {
	return &ReputationDatabase{
		packages:            make(map[string]*PackageReputation),
		packagesByManager:   make(map[string]map[string]*PackageReputation),
		trustedPackages:     make(map[string]bool),
		blacklistedPackages: make(map[string]bool),
		cacheExpiry:         make(map[string]time.Time),
		cacheTTL:            24 * time.Hour,
		lastUpdateTime:      time.Now(),
		updateInterval:      24 * time.Hour,
	}
}

// AddPackage adds or updates a package reputation record
func (db *ReputationDatabase) AddPackage(pkg *PackageReputation) error {
	if pkg == nil {
		return fmt.Errorf("package cannot be nil")
	}

	if pkg.Name == "" {
		return fmt.Errorf("package name is required")
	}

	db.mu.Lock()
	defer db.mu.Unlock()

	key := generatePackageKey(pkg.Name, pkg.PackageManager, pkg.Version)

	db.packages[key] = pkg
	pkg.LastUpdated = time.Now()

	// Index by package manager
	if db.packagesByManager[pkg.PackageManager] == nil {
		db.packagesByManager[pkg.PackageManager] = make(map[string]*PackageReputation)
	}
	db.packagesByManager[pkg.PackageManager][pkg.Name] = pkg

	// Set cache expiry
	db.cacheExpiry[key] = time.Now().Add(db.cacheTTL)

	// Update trust status
	if pkg.ReputationScore >= 80.0 {
		db.trustedPackages[key] = true
		delete(db.blacklistedPackages, key)
	} else if pkg.ReputationScore <= 20.0 || pkg.TrustLevel == MaliciousLevel {
		db.blacklistedPackages[key] = true
		delete(db.trustedPackages, key)
	} else {
		delete(db.trustedPackages, key)
		delete(db.blacklistedPackages, key)
	}

	return nil
}

// GetPackage retrieves a package reputation record
func (db *ReputationDatabase) GetPackage(name, manager string) *PackageReputation {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := generatePackageKey(name, manager, "")

	// Check cache validity
	if expiry, ok := db.cacheExpiry[key]; ok {
		if time.Now().After(expiry) {
			delete(db.cacheExpiry, key)
		}
	}

	return db.packages[key]
}

// GetPackageByNameAndVersion retrieves a specific version of a package
func (db *ReputationDatabase) GetPackageByNameAndVersion(name, manager, version string) *PackageReputation {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := generatePackageKey(name, manager, version)
	return db.packages[key]
}

// GetPackagesByManager retrieves all packages for a package manager
func (db *ReputationDatabase) GetPackagesByManager(manager string) []*PackageReputation {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if packages, ok := db.packagesByManager[manager]; ok {
		result := make([]*PackageReputation, 0, len(packages))
		for _, pkg := range packages {
			result = append(result, pkg)
		}
		return result
	}

	return make([]*PackageReputation, 0)
}

// GetTrustedPackages returns all trusted packages
func (db *ReputationDatabase) GetTrustedPackages() []*PackageReputation {
	db.mu.RLock()
	defer db.mu.RUnlock()

	result := make([]*PackageReputation, 0)
	for key := range db.trustedPackages {
		if pkg, ok := db.packages[key]; ok {
			result = append(result, pkg)
		}
	}

	return result
}

// GetBlacklistedPackages returns all blacklisted packages
func (db *ReputationDatabase) GetBlacklistedPackages() []*PackageReputation {
	db.mu.RLock()
	defer db.mu.RUnlock()

	result := make([]*PackageReputation, 0)
	for key := range db.blacklistedPackages {
		if pkg, ok := db.packages[key]; ok {
			result = append(result, pkg)
		}
	}

	return result
}

// IsTrusted checks if a package is trusted
func (db *ReputationDatabase) IsTrusted(name, manager string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := generatePackageKey(name, manager, "")
	return db.trustedPackages[key]
}

// IsBlacklisted checks if a package is blacklisted
func (db *ReputationDatabase) IsBlacklisted(name, manager string) bool {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := generatePackageKey(name, manager, "")
	return db.blacklistedPackages[key]
}

// GetReputationScore gets the reputation score for a package
func (db *ReputationDatabase) GetReputationScore(name, manager string) (float64, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := generatePackageKey(name, manager, "")
	pkg, ok := db.packages[key]
	if !ok {
		return 0, fmt.Errorf("package %s not found", name)
	}

	return pkg.ReputationScore, nil
}

// GetTrustLevel gets the trust level for a package
func (db *ReputationDatabase) GetTrustLevel(name, manager string) (string, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	key := generatePackageKey(name, manager, "")
	pkg, ok := db.packages[key]
	if !ok {
		return "", fmt.Errorf("package %s not found", name)
	}

	return pkg.TrustLevel, nil
}

// FindPackagesByTrustLevel finds all packages with a specific trust level
func (db *ReputationDatabase) FindPackagesByTrustLevel(level string) []*PackageReputation {
	db.mu.RLock()
	defer db.mu.RUnlock()

	result := make([]*PackageReputation, 0)
	for _, pkg := range db.packages {
		if pkg.TrustLevel == level {
			result = append(result, pkg)
		}
	}

	return result
}

// FindPackagesBySecurityIssues finds all packages with specific security issues
func (db *ReputationDatabase) FindPackagesBySecurityIssues(severity string) []*PackageReputation {
	db.mu.RLock()
	defer db.mu.RUnlock()

	result := make([]*PackageReputation, 0)
	for _, pkg := range db.packages {
		for _, issue := range pkg.SecurityIssues {
			if issue.Severity == severity {
				result = append(result, pkg)
				break
			}
		}
	}

	return result
}

// DeletePackage removes a package from the database
func (db *ReputationDatabase) DeletePackage(name, manager string) error {
	db.mu.Lock()
	defer db.mu.Unlock()

	key := generatePackageKey(name, manager, "")

	if _, ok := db.packages[key]; !ok {
		return fmt.Errorf("package %s not found", name)
	}

	delete(db.packages, key)
	delete(db.packagesByManager[manager], name)
	delete(db.trustedPackages, key)
	delete(db.blacklistedPackages, key)
	delete(db.cacheExpiry, key)

	return nil
}

// ClearCache clears expired cache entries
func (db *ReputationDatabase) ClearCache() int {
	db.mu.Lock()
	defer db.mu.Unlock()

	now := time.Now()
	expiredCount := 0

	for key, expiry := range db.cacheExpiry {
		if now.After(expiry) {
			delete(db.cacheExpiry, key)
			expiredCount++
		}
	}

	return expiredCount
}

// GetStatistics returns database statistics
func (db *ReputationDatabase) GetStatistics() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()

	criticalIssues := 0
	highIssues := 0
	mediumIssues := 0
	lowIssues := 0

	for _, pkg := range db.packages {
		for _, issue := range pkg.SecurityIssues {
			switch issue.Severity {
			case "critical":
				criticalIssues++
			case "high":
				highIssues++
			case "medium":
				mediumIssues++
			case "low":
				lowIssues++
			}
		}
	}

	return map[string]interface{}{
		"total_packages":      len(db.packages),
		"trusted_count":       len(db.trustedPackages),
		"blacklisted_count":   len(db.blacklistedPackages),
		"neutral_count":       len(db.packages) - len(db.trustedPackages) - len(db.blacklistedPackages),
		"cached_entries":      len(db.cacheExpiry),
		"critical_issues":     criticalIssues,
		"high_issues":         highIssues,
		"medium_issues":       mediumIssues,
		"low_issues":          lowIssues,
		"last_update":         db.lastUpdateTime,
	}
}

// UpdateDatabase performs a full database update
func (db *ReputationDatabase) UpdateDatabase(updates []*PackageReputation) error {
	if len(updates) == 0 {
		return fmt.Errorf("updates cannot be empty")
	}

	for _, pkg := range updates {
		if err := db.AddPackage(pkg); err != nil {
			return fmt.Errorf("failed to add package %s: %v", pkg.Name, err)
		}
	}

	db.mu.Lock()
	db.lastUpdateTime = time.Now()
	db.mu.Unlock()

	return nil
}

// FindSimilarPackages finds packages with similar names (typosquatting detection)
func (db *ReputationDatabase) FindSimilarPackages(name string, manager string) []*PackageReputation {
	db.mu.RLock()
	defer db.mu.RUnlock()

	result := make([]*PackageReputation, 0)
	if packages, ok := db.packagesByManager[manager]; ok {
		for pkgName, pkg := range packages {
			if isSimilarName(name, pkgName) && name != pkgName {
				result = append(result, pkg)
			}
		}
	}

	return result
}

// GetAverageCommunityRating returns average community rating across packages
func (db *ReputationDatabase) GetAverageCommunityRating() float64 {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if len(db.packages) == 0 {
		return 0
	}

	total := 0.0
	for _, pkg := range db.packages {
		total += pkg.CommunityRating
	}

	return total / float64(len(db.packages))
}

// GetMaintainerReputationMetrics returns metrics about maintainer reputation
func (db *ReputationDatabase) GetMaintainerReputationMetrics() map[string]interface{} {
	db.mu.RLock()
	defer db.mu.RUnlock()

	verifiedCount := 0
	avgTrustScore := 0.0
	totalMaintainers := 0

	for _, pkg := range db.packages {
		if pkg.MaintainerProfile != nil {
			totalMaintainers++
			if pkg.MaintainerProfile.VerifiedPublisher {
				verifiedCount++
			}
			avgTrustScore += pkg.MaintainerProfile.TrustScore
		}
	}

	if totalMaintainers > 0 {
		avgTrustScore /= float64(totalMaintainers)
	}

	return map[string]interface{}{
		"total_maintainers":      totalMaintainers,
		"verified_publishers":    verifiedCount,
		"avg_trust_score":        avgTrustScore,
		"organization_packages":  countOrganizationPackages(db.packages),
	}
}

// Helper functions

func generatePackageKey(name, manager, version string) string {
	if version != "" {
		return fmt.Sprintf("%s/%s@%s", manager, name, version)
	}
	return fmt.Sprintf("%s/%s", manager, name)
}

func isSimilarName(name1, name2 string) bool {
	// Simple similarity check (Levenshtein distance could be used)
	if len(name1) == 0 || len(name2) == 0 {
		return false
	}

	// Check for single character difference
	if len(name1) == len(name2) {
		diff := 0
		for i := 0; i < len(name1); i++ {
			if name1[i] != name2[i] {
				diff++
			}
		}
		return diff <= 2
	}

	// Check for substring similarity
	if len(name1) > 2 && len(name2) > 2 {
		minLen := len(name1)
		if len(name2) < minLen {
			minLen = len(name2)
		}

		matches := 0
		for i := 0; i < minLen; i++ {
			if name1[i] == name2[i] {
				matches++
			}
		}

		return float64(matches)/float64(minLen) >= 0.7
	}

	return false
}

func countOrganizationPackages(packages map[string]*PackageReputation) int {
	count := 0
	for _, pkg := range packages {
		if pkg.MaintainerProfile != nil && pkg.MaintainerProfile.IsOrganization {
			count++
		}
	}
	return count
}

// SetCacheTTL sets the cache time-to-live duration
func (db *ReputationDatabase) SetCacheTTL(ttl time.Duration) {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.cacheTTL = ttl
}

// GetSize returns the current size of the database
func (db *ReputationDatabase) GetSize() int {
	db.mu.RLock()
	defer db.mu.RUnlock()

	return len(db.packages)
}
