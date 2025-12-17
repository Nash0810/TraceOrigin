package remediation

import (
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

// RemediationType defines the type of remediation action
type RemediationType string

const (
	RemediationTypeUpdate        RemediationType = "update"
	RemediationTypeReplace       RemediationType = "replace"
	RemediationTypeRemove        RemediationType = "remove"
	RemediationTypePin           RemediationType = "pin"
	RemediationTypeAddSignature  RemediationType = "add-signature"
	RemediationTypeIsolate       RemediationType = "isolate"
	RemediationTypeBlock         RemediationType = "block"
	RemediationTypeReview        RemediationType = "review"
	RemediationTypeMonitor       RemediationType = "monitor"
)

// RemediationPriority defines the priority level
type RemediationPriority string

const (
	PriorityCritical RemediationPriority = "critical"
	PriorityHigh     RemediationPriority = "high"
	PriorityMedium   RemediationPriority = "medium"
	PriorityLow      RemediationPriority = "low"
	PriorityInfo     RemediationPriority = "info"
)

// RemediationStatus defines the status of remediation
type RemediationStatus string

const (
	StatusPending    RemediationStatus = "pending"
	StatusInProgress RemediationStatus = "in-progress"
	StatusCompleted  RemediationStatus = "completed"
	StatusFailed     RemediationStatus = "failed"
	StatusSkipped    RemediationStatus = "skipped"
)

// Remediation represents a single remediation action
type Remediation struct {
	ID              string
	PackageName     string
	CurrentVersion  string
	TargetVersion   string
	Type            RemediationType
	Priority        RemediationPriority
	Status          RemediationStatus
	Description     string
	Reason          string
	Steps           []RemediationStep
	TimeEstimate    time.Duration
	Impact          string
	RiskLevel       string
	Rollback        bool
	Automated       bool
	CreatedAt       time.Time
	CompletedAt     time.Time
	Metadata        map[string]interface{}
	Dependencies    []string
	Conflicts       []string
	Verification    *VerificationResult
	ApprovalRequired bool
	ApprovedBy      string
	ApprovedAt      time.Time
}

// RemediationStep represents a single step in the remediation process
type RemediationStep struct {
	ID          string
	Order       int
	Description string
	Command     string
	Status      string
	Error       string
	Duration    time.Duration
	ExecutedAt  time.Time
	Output      string
	Rollback    bool
	RollbackCmd string
	Timeout     time.Duration
}

// VerificationResult contains the result of remediation verification
type VerificationResult struct {
	Verified   bool
	Status     string
	Tests      []VerificationTest
	Duration   time.Duration
	CheckedAt  time.Time
	Confidence float64
}

// VerificationTest represents a single verification test
type VerificationTest struct {
	Name   string
	Passed bool
	Error  string
	Output string
}

// RemediationPlan represents a collection of remediations
type RemediationPlan struct {
	ID              string
	Name            string
	Description     string
	Remediations    []Remediation
	Priority        RemediationPriority
	CreatedAt       time.Time
	ScheduledFor    time.Time
	Status          RemediationStatus
	TotalSteps      int
	CompletedSteps  int
	FailedSteps     int
	Metadata        map[string]interface{}
	PreRequisites   []string
	PostActions     []string
	Rollback        bool
	MaxParallel     int
	TimeLimit       time.Duration
}

// RemediationEngine manages remediation operations
type RemediationEngine struct {
	remediations map[string]*Remediation
	plans        map[string]*RemediationPlan
	history      []Remediation
	mu           sync.RWMutex
	strategies   map[RemediationType]RemediationStrategy
	rules        []RemediationRule
	idCounter    int64
}

// RemediationStrategy defines how to handle a type of remediation
type RemediationStrategy interface {
	Execute(Remediation) error
	Validate(Remediation) error
	Rollback(Remediation) error
}

// RemediationRule defines a rule for generating remediations
type RemediationRule struct {
	ID              string
	Name            string
	Enabled         bool
	Condition       func(map[string]interface{}) bool
	RemediationType RemediationType
	Priority        RemediationPriority
	AutoApply       bool
	Description     string
}

// NewRemediationEngine creates a new remediation engine
func NewRemediationEngine() *RemediationEngine {
	return &RemediationEngine{
		remediations: make(map[string]*Remediation),
		plans:        make(map[string]*RemediationPlan),
		history:      make([]Remediation, 0),
		strategies:   make(map[RemediationType]RemediationStrategy),
		rules:        make([]RemediationRule, 0),
	}
}

// AddRemediation adds a remediation to the engine and returns the ID
func (re *RemediationEngine) AddRemediation(rem *Remediation) (string, error) {
	re.mu.Lock()
	defer re.mu.Unlock()

	if rem.ID == "" {
		re.idCounter++
		rem.ID = fmt.Sprintf("rem-%d-%d", time.Now().UnixNano(), re.idCounter)
	}
	if rem.CreatedAt.IsZero() {
		rem.CreatedAt = time.Now()
	}
	if rem.Status == "" {
		rem.Status = StatusPending
	}
	if rem.Metadata == nil {
		rem.Metadata = make(map[string]interface{})
	}

	if err := re.validateRemediation(*rem); err != nil {
		return "", err
	}

	re.remediations[rem.ID] = rem
	return rem.ID, nil
}

// GetRemediation retrieves a remediation by ID
func (re *RemediationEngine) GetRemediation(id string) (*Remediation, bool) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	rem, exists := re.remediations[id]
	return rem, exists
}

// ListRemediations returns all remediations with optional filtering
func (re *RemediationEngine) ListRemediations(status RemediationStatus) []Remediation {
	re.mu.RLock()
	defer re.mu.RUnlock()

	remediations := make([]Remediation, 0)
	for _, rem := range re.remediations {
		if status == "" || rem.Status == status {
			remediations = append(remediations, *rem)
		}
	}

	sort.Slice(remediations, func(i, j int) bool {
		priorityOrder := map[RemediationPriority]int{
			PriorityCritical: 0,
			PriorityHigh:     1,
			PriorityMedium:   2,
			PriorityLow:      3,
			PriorityInfo:     4,
		}
		return priorityOrder[remediations[i].Priority] < priorityOrder[remediations[j].Priority]
	})

	return remediations
}

// CreateRemediationPlan creates a plan with multiple remediations
func (re *RemediationEngine) CreateRemediationPlan(name string, remediationIDs []string) (*RemediationPlan, error) {
	re.mu.Lock()
	defer re.mu.Unlock()

	plan := &RemediationPlan{
		ID:           fmt.Sprintf("plan-%d", time.Now().UnixNano()),
		Name:         name,
		Remediations: make([]Remediation, 0),
		CreatedAt:    time.Now(),
		Status:       StatusPending,
		Metadata:     make(map[string]interface{}),
		MaxParallel:  1,
	}

	for _, id := range remediationIDs {
		rem, exists := re.remediations[id]
		if !exists {
			return nil, fmt.Errorf("remediation %q not found", id)
		}
		plan.Remediations = append(plan.Remediations, *rem)
		plan.TotalSteps += len(rem.Steps)
	}

	re.plans[plan.ID] = plan
	return plan, nil
}

// GetRemediationPlan retrieves a plan by ID
func (re *RemediationEngine) GetRemediationPlan(id string) (*RemediationPlan, bool) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	plan, exists := re.plans[id]
	return plan, exists
}

// ExecuteRemediation executes a single remediation
func (re *RemediationEngine) ExecuteRemediation(id string) error {
	re.mu.Lock()
	rem, exists := re.remediations[id]
	if !exists {
		re.mu.Unlock()
		return fmt.Errorf("remediation %q not found", id)
	}
	re.mu.Unlock()

	rem.Status = StatusInProgress

	for _, step := range rem.Steps {
		stepStartTime := time.Now()
		step.Status = "running"

		if step.Command != "" {
			// Execute command (in real implementation, would actually run)
			step.Output = fmt.Sprintf("Executed: %s", step.Command)
			step.Status = "completed"
		}

		step.Duration = time.Since(stepStartTime)
		step.ExecutedAt = time.Now()
	}

	rem.Status = StatusCompleted
	rem.CompletedAt = time.Now()

	re.mu.Lock()
	re.remediations[id] = rem
	re.history = append(re.history, *rem)
	re.mu.Unlock()

	return nil
}

// ExecuteRemediationPlan executes all remediations in a plan
func (re *RemediationEngine) ExecuteRemediationPlan(planID string) error {
	re.mu.RLock()
	plan, exists := re.plans[planID]
	if !exists {
		re.mu.RUnlock()
		return fmt.Errorf("plan %q not found", planID)
	}
	re.mu.RUnlock()

	plan.Status = StatusInProgress

	for _, rem := range plan.Remediations {
		if err := re.ExecuteRemediation(rem.ID); err != nil {
			plan.FailedSteps++
		} else {
			plan.CompletedSteps++
		}
	}

	plan.Status = StatusCompleted
	return nil
}

// GenerateRemediations generates remediations based on detected issues
func (re *RemediationEngine) GenerateRemediations(issues map[string]interface{}) ([]Remediation, error) {
	re.mu.RLock()
	rules := make([]RemediationRule, len(re.rules))
	copy(rules, re.rules)
	re.mu.RUnlock()

	remediations := make([]Remediation, 0)

	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}

		if rule.Condition != nil && rule.Condition(issues) {
			// Extract package name from issues if available
			pkgName := ""
			if pkg, ok := issues["package"].(string); ok {
				pkgName = pkg
			} else if pkg, ok := issues["PackageName"].(string); ok {
				pkgName = pkg
			}

			rem := Remediation{
				ID:              fmt.Sprintf("gen-%d", time.Now().UnixNano()),
				PackageName:     pkgName,
				Type:            rule.RemediationType,
				Priority:        rule.Priority,
				Status:          StatusPending,
				Description:     rule.Description,
				Automated:       rule.AutoApply,
				CreatedAt:       time.Now(),
				Metadata:        issues,
			}

			_, err := re.AddRemediation(&rem)
			if err != nil {
				return nil, err
			}

			remediations = append(remediations, rem)
		}
	}

	return remediations, nil
}

// AddRemediationRule adds a rule for generating remediations
func (re *RemediationEngine) AddRemediationRule(rule RemediationRule) {
	re.mu.Lock()
	defer re.mu.Unlock()

	if rule.ID == "" {
		rule.ID = fmt.Sprintf("rule-%d", time.Now().UnixNano())
	}

	re.rules = append(re.rules, rule)
}

// RollbackRemediation rolls back a completed remediation
func (re *RemediationEngine) RollbackRemediation(id string) error {
	re.mu.Lock()
	rem, exists := re.remediations[id]
	if !exists {
		re.mu.Unlock()
		return fmt.Errorf("remediation %q not found", id)
	}
	re.mu.Unlock()

	if rem.Status != StatusCompleted {
		return fmt.Errorf("can only rollback completed remediations")
	}

	if !rem.Rollback {
		return fmt.Errorf("rollback not available for this remediation")
	}

	// Reverse order of steps
	for i := len(rem.Steps) - 1; i >= 0; i-- {
		step := rem.Steps[i]
		if step.Rollback && step.RollbackCmd != "" {
			// Execute rollback command
			step.Output = fmt.Sprintf("Rolled back: %s", step.RollbackCmd)
		}
	}

	rem.Status = StatusPending
	rem.CompletedAt = time.Time{}

	re.mu.Lock()
	re.remediations[id] = rem
	re.mu.Unlock()

	return nil
}

// VerifyRemediation verifies that a remediation was successful
func (re *RemediationEngine) VerifyRemediation(id string) (*VerificationResult, error) {
	re.mu.RLock()
	rem, exists := re.remediations[id]
	if !exists {
		re.mu.RUnlock()
		return nil, fmt.Errorf("remediation %q not found", id)
	}
	re.mu.RUnlock()

	result := &VerificationResult{
		CheckedAt: time.Now(),
		Tests:     make([]VerificationTest, 0),
	}

	startTime := time.Now()

	// Run verification tests
	passedTests := 0
	for _, step := range rem.Steps {
		if step.Status == "completed" {
			test := VerificationTest{
				Name:   step.Description,
				Passed: step.Error == "",
				Output: step.Output,
			}
			if !test.Passed {
				test.Error = step.Error
			}
			result.Tests = append(result.Tests, test)
			if test.Passed {
				passedTests++
			}
		}
	}

	result.Duration = time.Since(startTime)
	if len(result.Tests) > 0 {
		result.Verified = passedTests == len(result.Tests)
		result.Confidence = float64(passedTests) / float64(len(result.Tests))
	}

	re.mu.Lock()
	rem.Verification = result
	re.remediations[id] = rem
	re.mu.Unlock()

	return result, nil
}

// ApproveRemediation approves a remediation for execution
func (re *RemediationEngine) ApproveRemediation(id string, approvedBy string) error {
	re.mu.Lock()
	defer re.mu.Unlock()

	rem, exists := re.remediations[id]
	if !exists {
		return fmt.Errorf("remediation %q not found", id)
	}

	if rem.Status != StatusPending {
		return fmt.Errorf("can only approve pending remediations")
	}

	rem.ApprovedBy = approvedBy
	rem.ApprovedAt = time.Now()

	re.remediations[id] = rem
	return nil
}

// GetRemediationHistory returns historical remediations
func (re *RemediationEngine) GetRemediationHistory() []Remediation {
	re.mu.RLock()
	defer re.mu.RUnlock()

	history := make([]Remediation, len(re.history))
	copy(history, re.history)
	return history
}

// GetRemediationsByType returns remediations filtered by type
func (re *RemediationEngine) GetRemediationsByType(remType RemediationType) []Remediation {
	re.mu.RLock()
	defer re.mu.RUnlock()

	remediations := make([]Remediation, 0)
	for _, rem := range re.remediations {
		if rem.Type == remType {
			remediations = append(remediations, *rem)
		}
	}
	return remediations
}

// GetRemediationsByPriority returns remediations filtered by priority
func (re *RemediationEngine) GetRemediationsByPriority(priority RemediationPriority) []Remediation {
	re.mu.RLock()
	defer re.mu.RUnlock()

	remediations := make([]Remediation, 0)
	for _, rem := range re.remediations {
		if rem.Priority == priority {
			remediations = append(remediations, *rem)
		}
	}
	return remediations
}

// GetRemediationStatistics returns statistics about remediations
func (re *RemediationEngine) GetRemediationStatistics() map[string]interface{} {
	re.mu.RLock()
	defer re.mu.RUnlock()

	stats := make(map[string]interface{})

	statusCounts := make(map[string]int)
	priorityCounts := make(map[string]int)
	typeCounts := make(map[string]int)
	totalSteps := 0
	completedSteps := 0

	for _, rem := range re.remediations {
		statusCounts[string(rem.Status)]++
		priorityCounts[string(rem.Priority)]++
		typeCounts[string(rem.Type)]++
		totalSteps += len(rem.Steps)

		for _, step := range rem.Steps {
			if step.Status == "completed" {
				completedSteps++
			}
		}
	}

	stats["total_remediations"] = len(re.remediations)
	stats["historical_remediations"] = len(re.history)
	stats["by_status"] = statusCounts
	stats["by_priority"] = priorityCounts
	stats["by_type"] = typeCounts
	stats["total_steps"] = totalSteps
	stats["completed_steps"] = completedSteps
	stats["completion_rate"] = float64(completedSteps) / float64(totalSteps) * 100

	return stats
}

// validateRemediation validates a remediation
func (re *RemediationEngine) validateRemediation(rem Remediation) error {
	if rem.PackageName == "" {
		return fmt.Errorf("package name is required")
	}

	if rem.Type == "" {
		return fmt.Errorf("remediation type is required")
	}

	if rem.Priority == "" {
		return fmt.Errorf("priority is required")
	}

	return nil
}

// ClearRemediations clears all remediations
func (re *RemediationEngine) ClearRemediations() {
	re.mu.Lock()
	defer re.mu.Unlock()

	re.remediations = make(map[string]*Remediation)
}

// EstimateRemediationTime estimates total time for remediations
func (re *RemediationEngine) EstimateRemediationTime(ids []string) time.Duration {
	re.mu.RLock()
	defer re.mu.RUnlock()

	totalTime := time.Duration(0)
	for _, id := range ids {
		if rem, exists := re.remediations[id]; exists {
			totalTime += rem.TimeEstimate
		}
	}
	return totalTime
}

// CheckRemediationConflicts checks for conflicts between remediations
func (re *RemediationEngine) CheckRemediationConflicts(id string) []string {
	re.mu.RLock()
	defer re.mu.RUnlock()

	rem, exists := re.remediations[id]
	if !exists {
		return []string{}
	}

	conflicts := make([]string, 0)
	for _, conflict := range rem.Conflicts {
		if _, exists := re.remediations[conflict]; exists {
			conflicts = append(conflicts, conflict)
		}
	}
	return conflicts
}

// SuggestRemediations suggests remediations based on criteria
func (re *RemediationEngine) SuggestRemediations(packageName string, severity string) []Remediation {
	re.mu.RLock()
	defer re.mu.RUnlock()

	suggested := make([]Remediation, 0)

	for _, rem := range re.remediations {
		if rem.PackageName == packageName && rem.Status == StatusPending {
			// Match by severity priority
			if severity == "critical" && rem.Priority == PriorityCritical {
				suggested = append(suggested, *rem)
			} else if severity == "high" && (rem.Priority == PriorityHigh || rem.Priority == PriorityCritical) {
				suggested = append(suggested, *rem)
			}
		}
	}

	return suggested
}

// ValidateRemediationPlan validates a remediation plan
func (re *RemediationEngine) ValidateRemediationPlan(planID string) []string {
	re.mu.RLock()
	defer re.mu.RUnlock()

	plan, exists := re.plans[planID]
	if !exists {
		return []string{"plan not found"}
	}

	errors := make([]string, 0)

	if plan.Name == "" {
		errors = append(errors, "plan name is required")
	}

	if len(plan.Remediations) == 0 {
		errors = append(errors, "plan has no remediations")
	}

	if plan.MaxParallel < 1 {
		errors = append(errors, "max_parallel must be >= 1")
	}

	return errors
}

// SearchRemediations searches remediations by package pattern
func (re *RemediationEngine) SearchRemediations(pattern string) ([]Remediation, error) {
	re.mu.RLock()
	defer re.mu.RUnlock()

	regex, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}

	results := make([]Remediation, 0)
	for _, rem := range re.remediations {
		if regex.MatchString(rem.PackageName) {
			results = append(results, *rem)
		}
	}

	return results, nil
}
