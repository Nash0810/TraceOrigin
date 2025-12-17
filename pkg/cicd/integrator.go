package cicd

import (
	"fmt"
	"regexp"
	"sort"
	"sync"
	"time"
)

// PipelineType defines the CI/CD platform type
type PipelineType string

const (
	PipelineGitHubActions PipelineType = "github-actions"
	PipelineGitLabCI      PipelineType = "gitlab-ci"
	PipelineJenkins       PipelineType = "jenkins"
	PipelineCircleCI      PipelineType = "circleci"
	PipelineTravisCI      PipelineType = "travis-ci"
	PipelineAzureDevOps   PipelineType = "azure-devops"
)

// PolicyLevel defines the enforcement level
type PolicyLevel string

const (
	PolicyWarning PolicyLevel = "warning"
	PolicyBlock   PolicyLevel = "block"
	PolicyAudit   PolicyLevel = "audit"
)

// PolicyType defines the type of policy being enforced
type PolicyType string

const (
	PolicyTypeVulnerability  PolicyType = "vulnerability"
	PolicyTypeReputation     PolicyType = "reputation"
	PolicyTypeVersion        PolicyType = "version"
	PolicyTypeLicense        PolicyType = "license"
	PolicyTypeSignature      PolicyType = "signature"
	PolicyTypeCVE            PolicyType = "cve"
	PolicyTypeTyposquatting  PolicyType = "typosquatting"
	PolicyTypeSupplyChain    PolicyType = "supply-chain"
)

// FailureReason documents why a policy check failed
type FailureReason struct {
	Type    PolicyType
	Reason  string
	Severity string
	Details map[string]interface{}
}

// PolicyResult contains the result of a policy check
type PolicyResult struct {
	Passed        bool
	FailureReasons []FailureReason
	ChecksDone    int
	ChecksPassed  int
	ChecksFailed  int
	ExecutedAt    time.Time
	Duration      time.Duration
}

// Policy defines a single policy rule
type Policy struct {
	ID              string
	Name            string
	Type            PolicyType
	Level           PolicyLevel
	Enabled         bool
	Threshold       int         // For vulnerability count, severity level, etc.
	Patterns        []string    // For regex matching
	ExcludedPackages []string   // Packages to exclude from policy
	Description     string
}

// PipelineConfig contains configuration for CI/CD integration
type PipelineConfig struct {
	Platform        PipelineType
	StrictMode      bool
	FailOnWarning   bool
	Policies        []Policy
	ExitOnFail      bool
	ReportPath      string
	MaxParallel     int
	Timeout         time.Duration
	NotificationURL string
}

// PipelineStep represents a single step in the CI/CD pipeline
type PipelineStep struct {
	ID          string
	Name        string
	Command     string
	Timeout     time.Duration
	Retries     int
	OnFailure   string // "fail", "warn", "continue"
	Environment map[string]string
	ExecutedAt  time.Time
	Duration    time.Duration
	Status      string // "pending", "running", "passed", "failed", "skipped"
	Output      string
	Error       string
}

// PipelineJob represents a CI/CD job execution
type PipelineJob struct {
	ID              string
	Name            string
	BuildNumber     int
	Status          string // "pending", "running", "passed", "failed", "error"
	Steps           []PipelineStep
	StartedAt       time.Time
	CompletedAt     time.Time
	Duration        time.Duration
	Artifacts       []string
	PolicyResults   PolicyResult
	Environment     map[string]string
	TriggeredBy     string
	Branch          string
	CommitHash      string
}

// CICDIntegrator manages CI/CD pipeline integration
type CICDIntegrator struct {
	platform       PipelineType
	config         PipelineConfig
	jobs           map[string]*PipelineJob
	policies       map[string]Policy
	history        []PipelineJob
	mu             sync.RWMutex
	policyPatterns map[string]*regexp.Regexp
}

// NewCICDIntegrator creates a new CI/CD integrator
func NewCICDIntegrator(pipelineType PipelineType) *CICDIntegrator {
	return &CICDIntegrator{
		platform:       pipelineType,
		jobs:           make(map[string]*PipelineJob),
		policies:       make(map[string]Policy),
		history:        make([]PipelineJob, 0),
		policyPatterns: make(map[string]*regexp.Regexp),
		config: PipelineConfig{
			Platform:    pipelineType,
			StrictMode:  false,
			FailOnWarning: false,
			ExitOnFail:  true,
			MaxParallel: 4,
			Timeout:     30 * time.Minute,
		},
	}
}

// AddPolicy adds a policy to the integrator
func (ci *CICDIntegrator) AddPolicy(policy Policy) error {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	// Compile regex patterns if provided
	for _, pattern := range policy.Patterns {
		if _, err := regexp.Compile(pattern); err != nil {
			return fmt.Errorf("invalid regex pattern %q: %v", pattern, err)
		}
	}

	ci.policies[policy.ID] = policy
	return nil
}

// GetPolicy retrieves a policy by ID
func (ci *CICDIntegrator) GetPolicy(policyID string) (Policy, bool) {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	policy, exists := ci.policies[policyID]
	return policy, exists
}

// ListPolicies returns all configured policies
func (ci *CICDIntegrator) ListPolicies() []Policy {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	policies := make([]Policy, 0, len(ci.policies))
	for _, policy := range ci.policies {
		if policy.Enabled {
			policies = append(policies, policy)
		}
	}
	return policies
}

// RemovePolicy removes a policy by ID
func (ci *CICDIntegrator) RemovePolicy(policyID string) {
	ci.mu.Lock()
	defer ci.mu.Unlock()
	delete(ci.policies, policyID)
}

// CreateJob creates a new pipeline job
func (ci *CICDIntegrator) CreateJob(name string, buildNumber int) *PipelineJob {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	jobID := fmt.Sprintf("%s-%d", name, buildNumber)
	job := &PipelineJob{
		ID:          jobID,
		Name:        name,
		BuildNumber: buildNumber,
		Status:      "pending",
		Steps:       make([]PipelineStep, 0),
		StartedAt:   time.Now(),
		Environment: make(map[string]string),
	}

	ci.jobs[jobID] = job
	return job
}

// AddStep adds a step to a job
func (ci *CICDIntegrator) AddStep(jobID string, step PipelineStep) error {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	job, exists := ci.jobs[jobID]
	if !exists {
		return fmt.Errorf("job %q not found", jobID)
	}

	if step.ID == "" {
		step.ID = fmt.Sprintf("step-%d", len(job.Steps)+1)
	}
	if step.Timeout == 0 {
		step.Timeout = 10 * time.Minute
	}
	if step.OnFailure == "" {
		step.OnFailure = "fail"
	}

	step.Status = "pending"
	job.Steps = append(job.Steps, step)
	return nil
}

// GetJob retrieves a job by ID
func (ci *CICDIntegrator) GetJob(jobID string) (*PipelineJob, bool) {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	job, exists := ci.jobs[jobID]
	return job, exists
}

// UpdateJobStatus updates a job's status
func (ci *CICDIntegrator) UpdateJobStatus(jobID string, status string) error {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	job, exists := ci.jobs[jobID]
	if !exists {
		return fmt.Errorf("job %q not found", jobID)
	}

	job.Status = status
	if status == "passed" || status == "failed" {
		job.CompletedAt = time.Now()
		job.Duration = job.CompletedAt.Sub(job.StartedAt)
	}
	return nil
}

// UpdateStepStatus updates a step's status within a job
func (ci *CICDIntegrator) UpdateStepStatus(jobID string, stepID string, status string, output string) error {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	job, exists := ci.jobs[jobID]
	if !exists {
		return fmt.Errorf("job %q not found", jobID)
	}

	for i := range job.Steps {
		if job.Steps[i].ID == stepID {
			job.Steps[i].Status = status
			job.Steps[i].Output = output
			job.Steps[i].ExecutedAt = time.Now()
			return nil
		}
	}

	return fmt.Errorf("step %q not found in job %q", stepID, jobID)
}

// CompleteStep marks a step as complete and returns the failure reason if failed
func (ci *CICDIntegrator) CompleteStep(jobID string, stepID string, passed bool, output string) (string, error) {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	job, exists := ci.jobs[jobID]
	if !exists {
		return "", fmt.Errorf("job %q not found", jobID)
	}

	for i := range job.Steps {
		if job.Steps[i].ID == stepID {
			if passed {
				job.Steps[i].Status = "passed"
			} else {
				job.Steps[i].Status = "failed"
			}
			job.Steps[i].Output = output
			job.Steps[i].Duration = time.Since(job.Steps[i].ExecutedAt)

			// Determine action on failure
			if !passed && job.Steps[i].OnFailure == "fail" {
				return "fail", nil
			}
			return job.Steps[i].OnFailure, nil
		}
	}

	return "", fmt.Errorf("step %q not found in job %q", stepID, jobID)
}

// ApplyPolicies applies all enabled policies to a job
func (ci *CICDIntegrator) ApplyPolicies(jobID string, packageData map[string]interface{}) (PolicyResult, error) {
	ci.mu.RLock()
	policies := make([]Policy, 0)
	for _, p := range ci.policies {
		if p.Enabled {
			policies = append(policies, p)
		}
	}
	ci.mu.RUnlock()

	result := PolicyResult{
		Passed:         true,
		FailureReasons: make([]FailureReason, 0),
		ExecutedAt:     time.Now(),
	}

	startTime := time.Now()
	for _, policy := range policies {
		result.ChecksDone++

		if ci.checkPolicy(policy, packageData) {
			result.ChecksPassed++
		} else {
			result.ChecksFailed++
			result.Passed = false
			reason := FailureReason{
				Type:       policy.Type,
				Reason:     policy.Name,
				Severity:   string(policy.Level),
				Details:    make(map[string]interface{}),
			}
			result.FailureReasons = append(result.FailureReasons, reason)
		}
	}

	result.Duration = time.Since(startTime)

	ci.mu.Lock()
	job, exists := ci.jobs[jobID]
	if exists {
		job.PolicyResults = result
	}
	ci.mu.Unlock()

	return result, nil
}

// checkPolicy evaluates a single policy against package data
func (ci *CICDIntegrator) checkPolicy(policy Policy, packageData map[string]interface{}) bool {
	switch policy.Type {
	case PolicyTypeVulnerability:
		if vulnCount, ok := packageData["vulnerability_count"].(int); ok {
			return vulnCount <= policy.Threshold
		}
	case PolicyTypeReputation:
		if score, ok := packageData["reputation_score"].(int); ok {
			return score >= policy.Threshold
		}
	case PolicyTypeCVE:
		if cves, ok := packageData["cves"].([]string); ok {
			return len(cves) <= policy.Threshold
		}
	case PolicyTypeTyposquatting:
		if typosquatted, ok := packageData["is_typosquatted"].(bool); ok {
			return !typosquatted
		}
	case PolicyTypeSignature:
		if signed, ok := packageData["is_signed"].(bool); ok {
			return signed
		}
	case PolicyTypeLicense:
		if license, ok := packageData["license"].(string); ok {
			for _, pattern := range policy.Patterns {
				if matched, _ := regexp.MatchString(pattern, license); matched {
					return true
				}
			}
			return len(policy.Patterns) == 0
		}
	}

	return true
}

// GetJobHistory returns the job execution history
func (ci *CICDIntegrator) GetJobHistory() []PipelineJob {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	history := make([]PipelineJob, len(ci.history))
	copy(history, ci.history)
	return history
}

// ArchiveJob moves a completed job to history
func (ci *CICDIntegrator) ArchiveJob(jobID string) error {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	job, exists := ci.jobs[jobID]
	if !exists {
		return fmt.Errorf("job %q not found", jobID)
	}

	if job.Status != "passed" && job.Status != "failed" {
		return fmt.Errorf("cannot archive job in %q status", job.Status)
	}

	ci.history = append(ci.history, *job)
	delete(ci.jobs, jobID)
	return nil
}

// GetStepLog retrieves the log output for a specific step
func (ci *CICDIntegrator) GetStepLog(jobID string, stepID string) (string, error) {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	job, exists := ci.jobs[jobID]
	if !exists {
		return "", fmt.Errorf("job %q not found", jobID)
	}

	for _, step := range job.Steps {
		if step.ID == stepID {
			return step.Output, nil
		}
	}

	return "", fmt.Errorf("step %q not found", stepID)
}

// GenerateReport generates a pipeline execution report
func (ci *CICDIntegrator) GenerateReport(jobID string) (map[string]interface{}, error) {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	job, exists := ci.jobs[jobID]
	if !exists {
		// Try to find in history
		for _, h := range ci.history {
			if h.ID == jobID {
				job = &h
				exists = true
				break
			}
		}
		if !exists {
			return nil, fmt.Errorf("job %q not found", jobID)
		}
	}

	report := map[string]interface{}{
		"job_id":        job.ID,
		"name":          job.Name,
		"build_number":  job.BuildNumber,
		"status":        job.Status,
		"started_at":    job.StartedAt,
		"completed_at":  job.CompletedAt,
		"duration":      job.Duration.String(),
		"branch":        job.Branch,
		"commit_hash":   job.CommitHash,
		"triggered_by":  job.TriggeredBy,
		"step_count":    len(job.Steps),
		"artifacts":     job.Artifacts,
		"policies_passed": job.PolicyResults.ChecksPassed,
		"policies_failed": job.PolicyResults.ChecksFailed,
		"policy_passed":   job.PolicyResults.Passed,
	}

	// Add step details
	steps := make([]map[string]interface{}, 0)
	for _, step := range job.Steps {
		stepData := map[string]interface{}{
			"id":        step.ID,
			"name":      step.Name,
			"status":    step.Status,
			"duration":  step.Duration.String(),
			"command":   step.Command,
		}
		steps = append(steps, stepData)
	}
	report["steps"] = steps

	return report, nil
}

// GetMetrics returns pipeline execution metrics
func (ci *CICDIntegrator) GetMetrics() map[string]interface{} {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	totalJobs := len(ci.jobs) + len(ci.history)
	passedJobs := 0
	failedJobs := 0
	totalDuration := time.Duration(0)
	policyFailures := make(map[string]int)

	allJobs := make([]PipelineJob, 0)
	for _, job := range ci.jobs {
		allJobs = append(allJobs, *job)
	}
	allJobs = append(allJobs, ci.history...)

	for _, job := range allJobs {
		if job.Status == "passed" {
			passedJobs++
		} else if job.Status == "failed" {
			failedJobs++
		}
		totalDuration += job.Duration

		for _, failure := range job.PolicyResults.FailureReasons {
			policyFailures[string(failure.Type)]++
		}
	}

	avgDuration := time.Duration(0)
	if totalJobs > 0 {
		avgDuration = totalDuration / time.Duration(totalJobs)
	}

	return map[string]interface{}{
		"total_jobs":        totalJobs,
		"passed_jobs":       passedJobs,
		"failed_jobs":       failedJobs,
		"success_rate":      float64(passedJobs) / float64(totalJobs) * 100,
		"total_duration":    totalDuration.String(),
		"average_duration":  avgDuration.String(),
		"policy_failures":   policyFailures,
		"active_jobs":       len(ci.jobs),
		"archived_jobs":     len(ci.history),
	}
}

// GeneratePipelineConfig creates a configuration for a specific platform
func (ci *CICDIntegrator) GeneratePipelineConfig(outputFormat string) string {
	switch ci.platform {
	case PipelineGitHubActions:
		return ci.generateGitHubActionsConfig()
	case PipelineGitLabCI:
		return ci.generateGitLabCIConfig()
	case PipelineJenkins:
		return ci.generateJenkinsConfig()
	default:
		return "# Unsupported platform"
	}
}

// generateGitHubActionsConfig generates GitHub Actions workflow config
func (ci *CICDIntegrator) generateGitHubActionsConfig() string {
	return `name: Supply Chain Security Check

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]

jobs:
  supply-chain-check:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Go
        uses: actions/setup-go@v4
        with:
          go-version: 1.21
      
      - name: Build TraceOrigin
        run: go build ./cmd/tracer -o tracer
      
      - name: Run supply chain analysis
        run: ./tracer analyze requirements.txt --strict --exit-code
      
      - name: Generate SBOM
        if: always()
        run: ./tracer sbom app_trace.json --output sbom.json
      
      - name: Upload SBOM
        if: always()
        uses: actions/upload-artifact@v3
        with:
          name: sbom
          path: sbom.json`
}

// generateGitLabCIConfig generates GitLab CI configuration
func (ci *CICDIntegrator) generateGitLabCIConfig() string {
	return `stages:
  - build
  - scan
  - report

supply-chain-scan:
  stage: scan
  image: golang:1.21
  script:
    - go build ./cmd/tracer -o tracer
    - ./tracer analyze requirements.txt --strict --exit-code
    - ./tracer sbom app_trace.json --output sbom.json
  artifacts:
    paths:
      - sbom.json
    expire_in: 30 days
  allow_failure: false`
}

// generateJenkinsConfig generates Jenkinsfile configuration
func (ci *CICDIntegrator) generateJenkinsConfig() string {
	return `pipeline {
  agent any
  
  stages {
    stage('Build') {
      steps {
        sh 'go build ./cmd/tracer -o tracer'
      }
    }
    
    stage('Supply Chain Analysis') {
      steps {
        sh './tracer analyze requirements.txt --strict --exit-code'
      }
    }
    
    stage('Generate SBOM') {
      steps {
        sh './tracer sbom app_trace.json --output sbom.json'
      }
    }
  }
  
  post {
    always {
      archiveArtifacts artifacts: 'sbom.json', fingerprint: true
    }
  }
}`
}

// ValidatePolicyConfiguration validates all configured policies
func (ci *CICDIntegrator) ValidatePolicyConfiguration() []string {
	ci.mu.RLock()
	defer ci.mu.RUnlock()

	errors := make([]string, 0)

	if len(ci.policies) == 0 {
		errors = append(errors, "no policies configured")
	}

	for _, policy := range ci.policies {
		if policy.ID == "" {
			errors = append(errors, "policy missing ID")
		}
		if policy.Name == "" {
			errors = append(errors, fmt.Sprintf("policy %q missing name", policy.ID))
		}
		for _, pattern := range policy.Patterns {
			if _, err := regexp.Compile(pattern); err != nil {
				errors = append(errors, fmt.Sprintf("policy %q has invalid regex: %v", policy.ID, err))
			}
		}
	}

	return errors
}

// SortPoliciesByPriority sorts policies by priority (vulnerability first, then others)
func (ci *CICDIntegrator) SortPoliciesByPriority() {
	ci.mu.Lock()
	defer ci.mu.Unlock()

	policies := make([]Policy, 0, len(ci.policies))
	for _, p := range ci.policies {
		policies = append(policies, p)
	}

	sort.Slice(policies, func(i, j int) bool {
		// Block policies first
		if policies[i].Level != policies[j].Level {
			return policies[i].Level == PolicyBlock
		}
		// Then by type priority
		typePriority := map[PolicyType]int{
			PolicyTypeVulnerability: 0,
			PolicyTypeCVE:           1,
			PolicyTypeTyposquatting: 2,
			PolicyTypeReputation:    3,
			PolicyTypeSignature:     4,
			PolicyTypeLicense:       5,
		}
		return typePriority[policies[i].Type] < typePriority[policies[j].Type]
	})

	ci.policies = make(map[string]Policy)
	for _, p := range policies {
		ci.policies[p.ID] = p
	}
}
