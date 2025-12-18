package tests

import (
	"fmt"
	"testing"

	"github.com/Nash0810/TraceOrigin/pkg/cicd"
)

func TestCICDIntegratorCreation(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)
	if integrator == nil {
		t.Fatal("failed to create CICD integrator")
	}
}

func TestAddPolicy(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	policy := cicd.Policy{
		ID:        "vuln-check",
		Name:      "Vulnerability Check",
		Type:      cicd.PolicyTypeVulnerability,
		Level:     cicd.PolicyBlock,
		Enabled:   true,
		Threshold: 5,
	}

	err := integrator.AddPolicy(policy)
	if err != nil {
		t.Fatalf("failed to add policy: %v", err)
	}

	retrieved, exists := integrator.GetPolicy("vuln-check")
	if !exists {
		t.Fatal("policy not found after adding")
	}
	if retrieved.Name != "Vulnerability Check" {
		t.Errorf("policy name mismatch: got %q, want %q", retrieved.Name, "Vulnerability Check")
	}
}

func TestAddInvalidPolicy(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	policy := cicd.Policy{
		ID:        "invalid-policy",
		Name:      "Invalid Policy",
		Type:      cicd.PolicyTypeLicense,
		Level:     cicd.PolicyBlock,
		Enabled:   true,
		Patterns:  []string{"[invalid(regex"},
	}

	err := integrator.AddPolicy(policy)
	if err == nil {
		t.Fatal("expected error for invalid regex pattern")
	}
}

func TestListPolicies(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	policies := []cicd.Policy{
		{ID: "policy-1", Name: "Policy 1", Type: cicd.PolicyTypeVulnerability, Level: cicd.PolicyBlock, Enabled: true},
		{ID: "policy-2", Name: "Policy 2", Type: cicd.PolicyTypeReputation, Level: cicd.PolicyWarning, Enabled: true},
		{ID: "policy-3", Name: "Policy 3", Type: cicd.PolicyTypeLicense, Level: cicd.PolicyAudit, Enabled: false},
	}

	for _, p := range policies {
		integrator.AddPolicy(p)
	}

	listed := integrator.ListPolicies()
	if len(listed) != 2 {
		t.Errorf("expected 2 enabled policies, got %d", len(listed))
	}
}

func TestRemovePolicy(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	policy := cicd.Policy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Type:    cicd.PolicyTypeVulnerability,
		Level:   cicd.PolicyBlock,
		Enabled: true,
	}

	integrator.AddPolicy(policy)
	integrator.RemovePolicy("test-policy")

	_, exists := integrator.GetPolicy("test-policy")
	if exists {
		t.Fatal("policy still exists after removal")
	}
}

func TestCreateJob(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	job := integrator.CreateJob("test-job", 123)
	if job == nil {
		t.Fatal("failed to create job")
	}
	if job.Name != "test-job" {
		t.Errorf("job name mismatch: got %q, want %q", job.Name, "test-job")
	}
	if job.BuildNumber != 123 {
		t.Errorf("job build number mismatch: got %d, want %d", job.BuildNumber, 123)
	}
	if job.Status != "pending" {
		t.Errorf("initial job status should be pending, got %q", job.Status)
	}
}

func TestAddStep(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)
	job := integrator.CreateJob("test-job", 1)

	step := cicd.PipelineStep{
		Name:    "Build",
		Command: "go build",
	}

	err := integrator.AddStep(job.ID, step)
	if err != nil {
		t.Fatalf("failed to add step: %v", err)
	}

	retrieved, exists := integrator.GetJob(job.ID)
	if !exists {
		t.Fatal("job not found")
	}
	if len(retrieved.Steps) != 1 {
		t.Errorf("expected 1 step, got %d", len(retrieved.Steps))
	}
}

func TestAddStepToNonexistentJob(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	step := cicd.PipelineStep{
		Name:    "Test",
		Command: "echo test",
	}

	err := integrator.AddStep("nonexistent", step)
	if err == nil {
		t.Fatal("expected error for nonexistent job")
	}
}

func TestUpdateJobStatus(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)
	job := integrator.CreateJob("test-job", 1)

	err := integrator.UpdateJobStatus(job.ID, "running")
	if err != nil {
		t.Fatalf("failed to update job status: %v", err)
	}

	retrieved, _ := integrator.GetJob(job.ID)
	if retrieved.Status != "running" {
		t.Errorf("job status mismatch: got %q, want %q", retrieved.Status, "running")
	}
}

func TestUpdateStepStatus(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)
	job := integrator.CreateJob("test-job", 1)

	step := cicd.PipelineStep{
		Name:    "Test",
		Command: "go test",
	}
	integrator.AddStep(job.ID, step)

	retrieved, _ := integrator.GetJob(job.ID)
	stepID := retrieved.Steps[0].ID

	err := integrator.UpdateStepStatus(job.ID, stepID, "running", "Running tests...")
	if err != nil {
		t.Fatalf("failed to update step status: %v", err)
	}

	retrieved, _ = integrator.GetJob(job.ID)
	if retrieved.Steps[0].Status != "running" {
		t.Errorf("step status mismatch: got %q, want %q", retrieved.Steps[0].Status, "running")
	}
}

func TestCompleteStep(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)
	job := integrator.CreateJob("test-job", 1)

	step := cicd.PipelineStep{
		Name:      "Test",
		Command:   "go test",
		OnFailure: "fail",
	}
	integrator.AddStep(job.ID, step)

	retrieved, _ := integrator.GetJob(job.ID)
	stepID := retrieved.Steps[0].ID

	action, err := integrator.CompleteStep(job.ID, stepID, true, "All tests passed")
	if err != nil {
		t.Fatalf("failed to complete step: %v", err)
	}
	if action != "fail" {
		t.Errorf("expected action %q, got %q", "fail", action)
	}

	retrieved, _ = integrator.GetJob(job.ID)
	if retrieved.Steps[0].Status != "passed" {
		t.Errorf("step status should be passed after completion")
	}
}

func TestApplyPolicies(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	// Add a vulnerability policy
	policy := cicd.Policy{
		ID:        "vuln-policy",
		Name:      "Vulnerability Check",
		Type:      cicd.PolicyTypeVulnerability,
		Level:     cicd.PolicyBlock,
		Enabled:   true,
		Threshold: 5,
	}
	integrator.AddPolicy(policy)

	job := integrator.CreateJob("test-job", 1)

	// Package data with low vulnerability count (should pass)
	packageData := map[string]interface{}{
		"vulnerability_count": 2,
	}

	result, err := integrator.ApplyPolicies(job.ID, packageData)
	if err != nil {
		t.Fatalf("failed to apply policies: %v", err)
	}
	if !result.Passed {
		t.Fatal("policies should pass for low vulnerability count")
	}
}

func TestApplyPoliciesFailure(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	policy := cicd.Policy{
		ID:        "vuln-policy",
		Name:      "Vulnerability Check",
		Type:      cicd.PolicyTypeVulnerability,
		Level:     cicd.PolicyBlock,
		Enabled:   true,
		Threshold: 5,
	}
	integrator.AddPolicy(policy)

	job := integrator.CreateJob("test-job", 1)

	// Package data with high vulnerability count (should fail)
	packageData := map[string]interface{}{
		"vulnerability_count": 10,
	}

	result, err := integrator.ApplyPolicies(job.ID, packageData)
	if err != nil {
		t.Fatalf("failed to apply policies: %v", err)
	}
	if result.Passed {
		t.Fatal("policies should fail for high vulnerability count")
	}
	if len(result.FailureReasons) == 0 {
		t.Fatal("should have failure reasons")
	}
}

func TestTyposquattingPolicy(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	policy := cicd.Policy{
		ID:      "typosquatting-policy",
		Name:    "Typosquatting Check",
		Type:    cicd.PolicyTypeTyposquatting,
		Level:   cicd.PolicyBlock,
		Enabled: true,
	}
	integrator.AddPolicy(policy)

	job := integrator.CreateJob("test-job", 1)

	// Test with typosquatted package
	packageData := map[string]interface{}{
		"is_typosquatted": true,
	}

	result, _ := integrator.ApplyPolicies(job.ID, packageData)
	if result.Passed {
		t.Fatal("should fail for typosquatted package")
	}
}

func TestSignaturePolicy(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	policy := cicd.Policy{
		ID:      "signature-policy",
		Name:    "Signature Check",
		Type:    cicd.PolicyTypeSignature,
		Level:   cicd.PolicyBlock,
		Enabled: true,
	}
	integrator.AddPolicy(policy)

	job := integrator.CreateJob("test-job", 1)

	packageData := map[string]interface{}{
		"is_signed": false,
	}

	result, _ := integrator.ApplyPolicies(job.ID, packageData)
	if result.Passed {
		t.Fatal("should fail for unsigned package")
	}
}

func TestGetStepLog(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)
	job := integrator.CreateJob("test-job", 1)

	step := cicd.PipelineStep{
		Name:    "Test",
		Command: "go test",
	}
	integrator.AddStep(job.ID, step)

	retrieved, _ := integrator.GetJob(job.ID)
	stepID := retrieved.Steps[0].ID

	integrator.UpdateStepStatus(job.ID, stepID, "passed", "All tests passed successfully")

	log, err := integrator.GetStepLog(job.ID, stepID)
	if err != nil {
		t.Fatalf("failed to get step log: %v", err)
	}
	if log != "All tests passed successfully" {
		t.Errorf("log mismatch: got %q", log)
	}
}

func TestGenerateReport(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)
	job := integrator.CreateJob("test-job", 42)

	step := cicd.PipelineStep{
		Name:    "Build",
		Command: "go build",
	}
	integrator.AddStep(job.ID, step)

	integrator.UpdateJobStatus(job.ID, "passed")

	report, err := integrator.GenerateReport(job.ID)
	if err != nil {
		t.Fatalf("failed to generate report: %v", err)
	}

	if report["name"] != "test-job" {
		t.Errorf("report name mismatch")
	}
	if report["build_number"] != 42 {
		t.Errorf("report build number mismatch")
	}
	if report["status"] != "passed" {
		t.Errorf("report status mismatch")
	}
}

func TestArchiveJob(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)
	job := integrator.CreateJob("test-job", 1)

	integrator.UpdateJobStatus(job.ID, "passed")

	err := integrator.ArchiveJob(job.ID)
	if err != nil {
		t.Fatalf("failed to archive job: %v", err)
	}

	_, exists := integrator.GetJob(job.ID)
	if exists {
		t.Fatal("job should not exist after archiving")
	}

	history := integrator.GetJobHistory()
	if len(history) != 1 {
		t.Errorf("expected 1 job in history, got %d", len(history))
	}
}

func TestGetJobHistory(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	for i := 0; i < 5; i++ {
		job := integrator.CreateJob(fmt.Sprintf("job-%d", i), i)
		integrator.UpdateJobStatus(job.ID, "passed")
		integrator.ArchiveJob(job.ID)
	}

	history := integrator.GetJobHistory()
	if len(history) != 5 {
		t.Errorf("expected 5 jobs in history, got %d", len(history))
	}
}

func TestGetMetrics(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	// Create and complete some jobs
	for i := 0; i < 3; i++ {
		job := integrator.CreateJob(fmt.Sprintf("job-%d", i), i)
		integrator.UpdateJobStatus(job.ID, "passed")
		integrator.ArchiveJob(job.ID)
	}

	metrics := integrator.GetMetrics()

	if metrics["total_jobs"] != 3 {
		t.Errorf("expected 3 total jobs in metrics, got %v", metrics["total_jobs"])
	}
	if metrics["passed_jobs"] != 3 {
		t.Errorf("expected 3 passed jobs in metrics, got %v", metrics["passed_jobs"])
	}
}

func TestGeneratePipelineConfig(t *testing.T) {
	tests := []struct {
		platform cicd.PipelineType
		keyword  string
	}{
		{cicd.PipelineGitHubActions, "actions"},
		{cicd.PipelineGitLabCI, "stages"},
		{cicd.PipelineJenkins, "pipeline"},
	}

	for _, tt := range tests {
		integrator := cicd.NewCICDIntegrator(tt.platform)
		config := integrator.GeneratePipelineConfig("")

		if len(config) == 0 {
			t.Errorf("empty config for platform %v", tt.platform)
		}
	}
}

func TestValidatePolicyConfiguration(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	errors := integrator.ValidatePolicyConfiguration()
	if len(errors) == 0 {
		t.Fatal("should have errors for empty configuration")
	}

	policy := cicd.Policy{
		ID:      "test-policy",
		Name:    "Test Policy",
		Type:    cicd.PolicyTypeVulnerability,
		Level:   cicd.PolicyBlock,
		Enabled: true,
	}
	integrator.AddPolicy(policy)

	errors = integrator.ValidatePolicyConfiguration()
	if len(errors) > 0 {
		t.Errorf("expected no errors after adding valid policy, got %v", errors)
	}
}

func TestSortPoliciesByPriority(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	// Add policies in random order
	policies := []cicd.Policy{
		{ID: "license", Name: "License", Type: cicd.PolicyTypeLicense, Level: cicd.PolicyWarning, Enabled: true},
		{ID: "vuln", Name: "Vulnerability", Type: cicd.PolicyTypeVulnerability, Level: cicd.PolicyBlock, Enabled: true},
		{ID: "sig", Name: "Signature", Type: cicd.PolicyTypeSignature, Level: cicd.PolicyWarning, Enabled: true},
		{ID: "typo", Name: "Typosquatting", Type: cicd.PolicyTypeTyposquatting, Level: cicd.PolicyBlock, Enabled: true},
	}

	for _, p := range policies {
		integrator.AddPolicy(p)
	}

	integrator.SortPoliciesByPriority()

	sorted := integrator.ListPolicies()
	if sorted[0].Type != cicd.PolicyTypeVulnerability {
		t.Errorf("vulnerability policy should be first")
	}
}

func TestConcurrentJobCreation(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(index int) {
			integrator.CreateJob(fmt.Sprintf("job-%d", index), index)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	metrics := integrator.GetMetrics()
	if metrics["active_jobs"] != 10 {
		t.Errorf("expected 10 active jobs, got %v", metrics["active_jobs"])
	}
}

func TestPolicyWithExcludedPackages(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	policy := cicd.Policy{
		ID:               "test-policy",
		Name:             "Test Policy",
		Type:             cicd.PolicyTypeVulnerability,
		Level:            cicd.PolicyBlock,
		Enabled:          true,
		ExcludedPackages: []string{"safe-package"},
	}

	err := integrator.AddPolicy(policy)
	if err != nil {
		t.Fatalf("failed to add policy: %v", err)
	}

	retrieved, _ := integrator.GetPolicy("test-policy")
	if len(retrieved.ExcludedPackages) != 1 {
		t.Errorf("excluded packages not stored properly")
	}
}

func TestPolicyDescription(t *testing.T) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	policy := cicd.Policy{
		ID:          "test-policy",
		Name:        "Test Policy",
		Type:        cicd.PolicyTypeVulnerability,
		Level:       cicd.PolicyBlock,
		Enabled:     true,
		Description: "This is a test policy",
	}

	err := integrator.AddPolicy(policy)
	if err != nil {
		t.Fatalf("failed to add policy: %v", err)
	}

	retrieved, _ := integrator.GetPolicy("test-policy")
	if retrieved.Description != "This is a test policy" {
		t.Errorf("description mismatch")
	}
}

// Benchmarks

func BenchmarkCreateJob(b *testing.B) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrator.CreateJob("job", i)
	}
}

func BenchmarkAddStep(b *testing.B) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)
	job := integrator.CreateJob("job", 1)

	step := cicd.PipelineStep{
		Name:    "Test",
		Command: "go test",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrator.AddStep(job.ID, step)
	}
}

func BenchmarkApplyPolicies(b *testing.B) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)

	policy := cicd.Policy{
		ID:        "test",
		Name:      "Test",
		Type:      cicd.PolicyTypeVulnerability,
		Level:     cicd.PolicyBlock,
		Enabled:   true,
		Threshold: 5,
	}
	integrator.AddPolicy(policy)

	job := integrator.CreateJob("job", 1)
	packageData := map[string]interface{}{
		"vulnerability_count": 2,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrator.ApplyPolicies(job.ID, packageData)
	}
}

func BenchmarkGenerateReport(b *testing.B) {
	integrator := cicd.NewCICDIntegrator(cicd.PipelineGitHubActions)
	job := integrator.CreateJob("job", 1)
	integrator.UpdateJobStatus(job.ID, "passed")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		integrator.GenerateReport(job.ID)
	}
}
