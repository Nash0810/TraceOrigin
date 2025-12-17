package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/Nash0810/TraceOrigin/pkg/remediation"
)

func TestRemediationEngineCreation(t *testing.T) {
	engine := remediation.NewRemediationEngine()
	if engine == nil {
		t.Fatal("failed to create remediation engine")
	}
}

func TestAddRemediation(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName:    "requests",
		CurrentVersion: "2.25.0",
		TargetVersion:  "2.28.0",
		Type:           remediation.RemediationTypeUpdate,
		Priority:       remediation.PriorityHigh,
		Description:    "Update to patched version",
	}

	id, err := engine.AddRemediation(&rem)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}
	if id == "" {
		t.Fatal("received empty ID from AddRemediation")
	}
}

func TestAddRemediationWithoutPackageName(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		Type:     remediation.RemediationTypeUpdate,
		Priority: remediation.PriorityHigh,
	}

	_, err := engine.AddRemediation(&rem)
	if err == nil {
		t.Fatal("expected error for missing package name")
	}
}

func TestGetRemediation(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName:    "requests",
		Type:           remediation.RemediationTypeUpdate,
		Priority:       remediation.PriorityHigh,
		Description:    "Test remediation",
	}

	id, err := engine.AddRemediation(&rem)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}

	retrieved, exists := engine.GetRemediation(id)
	if !exists {
		t.Fatal("remediation not found")
	}

	if retrieved.PackageName != "requests" {
		t.Errorf("package name mismatch")
	}
}

func TestListRemediations(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	remediations := []remediation.Remediation{
		{PackageName: "pkg1", Type: remediation.RemediationTypeUpdate, Priority: remediation.PriorityCritical},
		{PackageName: "pkg2", Type: remediation.RemediationTypeUpdate, Priority: remediation.PriorityHigh},
		{PackageName: "pkg3", Type: remediation.RemediationTypeRemove, Priority: remediation.PriorityMedium},
	}

	ids := make([]string, 0)
	for i := range remediations {
		id, err := engine.AddRemediation(&remediations[i])
		if err != nil {
			t.Fatalf("failed to add remediation: %v", err)
		}
		ids = append(ids, id)
	}

	listed := engine.ListRemediations("")
	if len(listed) != 3 {
		t.Errorf("expected 3 remediations, got %d", len(listed))
	}

	// Check priority ordering
	if listed[0].Priority != remediation.PriorityCritical {
		t.Error("critical priority should be first")
	}
}

func TestCreateRemediationPlan(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem1 := remediation.Remediation{
		PackageName: "pkg1",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityHigh,
	}
	rem2 := remediation.Remediation{
		PackageName: "pkg2",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityMedium,
	}

	id1, err := engine.AddRemediation(&rem1)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}
	id2, err := engine.AddRemediation(&rem2)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}

	plan, err := engine.CreateRemediationPlan("test-plan", []string{id1, id2})
	if err != nil {
		t.Fatalf("failed to create plan: %v", err)
	}

	if plan.Name != "test-plan" {
		t.Errorf("plan name mismatch")
	}
	if len(plan.Remediations) != 2 {
		t.Errorf("expected 2 remediations in plan, got %d", len(plan.Remediations))
	}
}

func TestCreateRemediationPlanWithInvalidID(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	_, err := engine.CreateRemediationPlan("test-plan", []string{"nonexistent-id"})
	if err == nil {
		t.Fatal("expected error for nonexistent remediation")
	}
}

func TestExecuteRemediation(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName:    "requests",
		Type:           remediation.RemediationTypeUpdate,
		Priority:       remediation.PriorityHigh,
		Status:         remediation.StatusPending,
		TimeEstimate:   5 * time.Second,
		Steps: []remediation.RemediationStep{
			{
				ID:          "step1",
				Order:       1,
				Description: "Update package",
				Command:     "pip install requests==2.28.0",
			},
		},
	}

	id, err := engine.AddRemediation(&rem)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}
	err = engine.ExecuteRemediation(id)
	if err != nil {
		t.Fatalf("failed to execute remediation: %v", err)
	}

	executed, exists := engine.GetRemediation(id)
	if !exists {
		t.Fatal("executed remediation not found")
	}
	if executed.Status != remediation.StatusCompleted {
		t.Errorf("remediation status should be completed, got %s", executed.Status)
	}
}

func TestExecuteRemediationPlan(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem1 := remediation.Remediation{
		PackageName: "pkg1",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityHigh,
		Steps: []remediation.RemediationStep{
			{ID: "step1", Description: "Update pkg1", Command: "update pkg1"},
		},
	}
	rem2 := remediation.Remediation{
		PackageName: "pkg2",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityMedium,
		Steps: []remediation.RemediationStep{
			{ID: "step1", Description: "Update pkg2", Command: "update pkg2"},
		},
	}

	id1, err := engine.AddRemediation(&rem1)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}
	id2, err := engine.AddRemediation(&rem2)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}

	plan, _ := engine.CreateRemediationPlan("test-plan", []string{id1, id2})

	err = engine.ExecuteRemediationPlan(plan.ID)
	if err != nil {
		t.Fatalf("failed to execute plan: %v", err)
	}

	retrieved, _ := engine.GetRemediationPlan(plan.ID)
	if retrieved.Status != remediation.StatusCompleted {
		t.Errorf("plan status should be completed")
	}
}

func TestGenerateRemediations(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rule := remediation.RemediationRule{
		Name:            "Update vulnerable packages",
		Enabled:         true,
		RemediationType: remediation.RemediationTypeUpdate,
		Priority:        remediation.PriorityCritical,
		Condition: func(issues map[string]interface{}) bool {
			severity, ok := issues["severity"].(string)
			return ok && severity == "critical"
		},
	}

	engine.AddRemediationRule(rule)

	issues := map[string]interface{}{
		"package":  "flask",
		"severity": "critical",
	}

	remediations, err := engine.GenerateRemediations(issues)
	if err != nil {
		t.Fatalf("failed to generate remediations: %v", err)
	}

	if len(remediations) != 1 {
		t.Errorf("expected 1 generated remediation, got %d", len(remediations))
	}
}

func TestRollbackRemediation(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName: "requests",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityHigh,
		Rollback:    true,
		Status:      remediation.StatusCompleted,
		CompletedAt: time.Now(),
		Steps: []remediation.RemediationStep{
			{
				ID:          "step1",
				Description: "Update",
				Command:     "update",
				Status:      "completed",
				RollbackCmd: "rollback",
				Rollback:    true,
			},
		},
	}

	engine.AddRemediation(&rem)

	err := engine.RollbackRemediation(rem.ID)
	if err != nil {
		t.Fatalf("failed to rollback: %v", err)
	}

	rolled, _ := engine.GetRemediation(rem.ID)
	if rolled.Status != remediation.StatusPending {
		t.Errorf("rolled back remediation should be pending")
	}
}

func TestVerifyRemediation(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName: "requests",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityHigh,
		Status:      remediation.StatusCompleted,
		Steps: []remediation.RemediationStep{
			{
				ID:          "step1",
				Description: "Verification test",
				Status:      "completed",
				Error:       "",
				Output:      "Success",
			},
		},
	}

	id, err := engine.AddRemediation(&rem)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}

	result, err := engine.VerifyRemediation(id)
	if err != nil {
		t.Fatalf("failed to verify: %v", err)
	}

	if !result.Verified {
		t.Error("verification should pass")
	}
	if result.Confidence != 1.0 {
		t.Errorf("confidence should be 1.0, got %f", result.Confidence)
	}
}

func TestApproveRemediation(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName:     "requests",
		Type:            remediation.RemediationTypeUpdate,
		Priority:        remediation.PriorityHigh,
		ApprovalRequired: true,
	}

	id, err := engine.AddRemediation(&rem)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}

	err = engine.ApproveRemediation(id, "admin")
	if err != nil {
		t.Fatalf("failed to approve: %v", err)
	}

	approved, _ := engine.GetRemediation(rem.ID)
	if approved.ApprovedBy != "admin" {
		t.Errorf("approved by mismatch")
	}
}

func TestGetRemediationHistory(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName: "requests",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityHigh,
		Steps: []remediation.RemediationStep{
			{ID: "step1", Description: "Test", Command: "test"},
		},
	}

	id, err := engine.AddRemediation(&rem)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}
	engine.ExecuteRemediation(id)

	history := engine.GetRemediationHistory()
	if len(history) != 1 {
		t.Errorf("expected 1 historical remediation, got %d", len(history))
	}
}

func TestGetRemediationsByType(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	remediations := []remediation.Remediation{
		{PackageName: "pkg1", Type: remediation.RemediationTypeUpdate, Priority: remediation.PriorityHigh},
		{PackageName: "pkg2", Type: remediation.RemediationTypeUpdate, Priority: remediation.PriorityMedium},
		{PackageName: "pkg3", Type: remediation.RemediationTypeRemove, Priority: remediation.PriorityLow},
	}

	for i := range remediations {
		_, err := engine.AddRemediation(&remediations[i])
		if err != nil {
			t.Fatalf("failed to add remediation: %v", err)
		}
	}

	updates := engine.GetRemediationsByType(remediation.RemediationTypeUpdate)
	if len(updates) != 2 {
		t.Errorf("expected 2 update remediations, got %d", len(updates))
	}
}

func TestGetRemediationsByPriority(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	remediations := []remediation.Remediation{
		{PackageName: "pkg1", Type: remediation.RemediationTypeUpdate, Priority: remediation.PriorityCritical},
		{PackageName: "pkg2", Type: remediation.RemediationTypeUpdate, Priority: remediation.PriorityHigh},
		{PackageName: "pkg3", Type: remediation.RemediationTypeRemove, Priority: remediation.PriorityCritical},
	}

	for i := range remediations {
		_, err := engine.AddRemediation(&remediations[i])
		if err != nil {
			t.Fatalf("failed to add remediation: %v", err)
		}
	}

	critical := engine.GetRemediationsByPriority(remediation.PriorityCritical)
	if len(critical) != 2 {
		t.Errorf("expected 2 critical remediations, got %d", len(critical))
	}
}

func TestGetRemediationStatistics(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	remediations := []remediation.Remediation{
		{PackageName: "pkg1", Type: remediation.RemediationTypeUpdate, Priority: remediation.PriorityCritical},
		{PackageName: "pkg2", Type: remediation.RemediationTypeUpdate, Priority: remediation.PriorityHigh},
		{PackageName: "pkg3", Type: remediation.RemediationTypeRemove, Priority: remediation.PriorityMedium},
	}

	for _, rem := range remediations {
		_, err := engine.AddRemediation(&rem)
		if err != nil {
			t.Fatalf("failed to add remediation: %v", err)
		}
	}

	stats := engine.GetRemediationStatistics()

	if stats["total_remediations"] != 3 {
		t.Errorf("expected 3 total remediations")
	}
}

func TestClearRemediations(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName: "requests",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityHigh,
	}

	id, err := engine.AddRemediation(&rem)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}
	engine.ClearRemediations()

	_, exists := engine.GetRemediation(id)
	if exists {
		t.Fatal("remediation should not exist after clear")
	}
}

func TestEstimateRemediationTime(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem1 := remediation.Remediation{
		PackageName:  "pkg1",
		Type:         remediation.RemediationTypeUpdate,
		Priority:     remediation.PriorityHigh,
		TimeEstimate: 5 * time.Minute,
	}
	rem2 := remediation.Remediation{
		PackageName:  "pkg2",
		Type:         remediation.RemediationTypeUpdate,
		Priority:     remediation.PriorityMedium,
		TimeEstimate: 3 * time.Minute,
	}

	id1, err := engine.AddRemediation(&rem1)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}
	id2, err := engine.AddRemediation(&rem2)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}

	totalTime := engine.EstimateRemediationTime([]string{id1, id2})
	expected := 8 * time.Minute

	if totalTime != expected {
		t.Errorf("expected %v, got %v", expected, totalTime)
	}
}

func TestCheckRemediationConflicts(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem1 := remediation.Remediation{
		PackageName: "pkg1",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityHigh,
	}
	rem2 := remediation.Remediation{
		PackageName: "pkg2",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityMedium,
	}

	id1, err := engine.AddRemediation(&rem1)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}
	id2, err := engine.AddRemediation(&rem2)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}

	// Set conflict
	rem1.Conflicts = []string{id2}
	engine.AddRemediation(&rem1)

	conflicts := engine.CheckRemediationConflicts(id1)
	if len(conflicts) != 1 {
		t.Errorf("expected 1 conflict, got %d", len(conflicts))
	}
}

func TestSuggestRemediations(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName: "requests",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityCritical,
		Status:      remediation.StatusPending,
	}

	_, err := engine.AddRemediation(&rem)
	if err != nil {
		t.Fatalf("failed to add remediation: %v", err)
	}

	suggested := engine.SuggestRemediations("requests", "critical")
	if len(suggested) != 1 {
		t.Errorf("expected 1 suggested remediation, got %d", len(suggested))
	}
}

func TestValidateRemediationPlan(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName: "pkg1",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityHigh,
	}

	id, _ := engine.AddRemediation(&rem)

	plan, _ := engine.CreateRemediationPlan("test-plan", []string{id})

	errors := engine.ValidateRemediationPlan(plan.ID)
	if len(errors) > 0 {
		t.Errorf("expected no validation errors, got %v", errors)
	}
}

func TestSearchRemediations(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	remediations := []remediation.Remediation{
		{PackageName: "flask-app", Type: remediation.RemediationTypeUpdate, Priority: remediation.PriorityHigh},
		{PackageName: "django-rest", Type: remediation.RemediationTypeUpdate, Priority: remediation.PriorityMedium},
		{PackageName: "flask-cors", Type: remediation.RemediationTypeRemove, Priority: remediation.PriorityLow},
	}

	for i := range remediations {
		_, err := engine.AddRemediation(&remediations[i])
		if err != nil {
			t.Fatalf("failed to add remediation: %v", err)
		}
	}

	results, err := engine.SearchRemediations("flask.*")
	if err != nil {
		t.Fatalf("search failed: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("expected 2 results matching flask pattern, got %d", len(results))
	}
}

func TestConcurrentRemediationAddition(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(index int) {
			rem := remediation.Remediation{
				PackageName: fmt.Sprintf("pkg%d", index),
				Type:        remediation.RemediationTypeUpdate,
				Priority:    remediation.PriorityHigh,
			}
			engine.AddRemediation(&rem)
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	listed := engine.ListRemediations("")
	if len(listed) != 10 {
		t.Errorf("expected 10 remediations, got %d", len(listed))
	}
}

func TestRemediationMetadata(t *testing.T) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName: "requests",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityHigh,
		Metadata: map[string]interface{}{
			"cve_id":     "CVE-2021-12345",
			"verified":   true,
			"confidence": 0.95,
		},
	}

	id, _ := engine.AddRemediation(&rem)

	retrieved, _ := engine.GetRemediation(id)
	if retrieved.Metadata["cve_id"] != "CVE-2021-12345" {
		t.Error("metadata not preserved")
	}
}

// Benchmarks

func BenchmarkAddRemediation(b *testing.B) {
	engine := remediation.NewRemediationEngine()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rem := remediation.Remediation{
			PackageName: fmt.Sprintf("pkg%d", i),
			Type:        remediation.RemediationTypeUpdate,
			Priority:    remediation.PriorityHigh,
		}
		_, _ = engine.AddRemediation(&rem)
	}
}

func BenchmarkExecuteRemediation(b *testing.B) {
	engine := remediation.NewRemediationEngine()

	rem := remediation.Remediation{
		PackageName: "requests",
		Type:        remediation.RemediationTypeUpdate,
		Priority:    remediation.PriorityHigh,
		Steps: []remediation.RemediationStep{
			{ID: "step1", Description: "Test", Command: "test"},
		},
	}

	id, _ := engine.AddRemediation(&rem)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.ExecuteRemediation(id)
	}
}

func BenchmarkGetRemediationStatistics(b *testing.B) {
	engine := remediation.NewRemediationEngine()

	for i := 0; i < 100; i++ {
		rem := remediation.Remediation{
			PackageName: fmt.Sprintf("pkg%d", i),
			Type:        remediation.RemediationTypeUpdate,
			Priority:    remediation.PriorityHigh,
		}
		_, _ = engine.AddRemediation(&rem)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.GetRemediationStatistics()
	}
}

func BenchmarkSearchRemediations(b *testing.B) {
	engine := remediation.NewRemediationEngine()

	for i := 0; i < 100; i++ {
		rem := remediation.Remediation{
			PackageName: fmt.Sprintf("flask-pkg%d", i),
			Type:        remediation.RemediationTypeUpdate,
			Priority:    remediation.PriorityHigh,
		}
		_, _ = engine.AddRemediation(&rem)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.SearchRemediations("flask.*")
	}
}
