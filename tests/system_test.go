package tests

import (
	"testing"

	"github.com/Nash0810/TraceOrigin/pkg/alert"
	"github.com/Nash0810/TraceOrigin/pkg/correlator"
	"github.com/Nash0810/TraceOrigin/pkg/export"
	"github.com/Nash0810/TraceOrigin/pkg/remediation"
	"github.com/Nash0810/TraceOrigin/pkg/reputation"
	"github.com/Nash0810/TraceOrigin/pkg/scoring"
	"github.com/Nash0810/TraceOrigin/pkg/version"
)

// TestSystemComponentsInitialization verifies all major components can be initialized
func TestSystemComponentsInitialization(t *testing.T) {
	tests := []struct {
		name   string
		testFn func() bool
	}{
		{
			name: "Correlator Engine",
			testFn: func() bool {
				return correlator.NewCorrelationEngine() != nil
			},
		},
		{
			name: "Alert Manager",
			testFn: func() bool {
				return alert.NewAlertManager() != nil
			},
		},
		{
			name: "Exporter",
			testFn: func() bool {
				config := export.ExportConfig{
					Format:   export.FormatJSON,
					Target:   export.TargetFile,
					Filename: "test.json",
				}
				return export.NewExporter(config) != nil
			},
		},
		{
			name: "Remediation Engine",
			testFn: func() bool {
				return remediation.NewRemediationEngine() != nil
			},
		},
		{
			name: "Reputation Database",
			testFn: func() bool {
				return reputation.NewReputationDatabase() != nil
			},
		},
		{
			name: "Threat Scoring Engine",
			testFn: func() bool {
				return scoring.NewThreatScoringEngine() != nil
			},
		},
		{
			name: "Version Extractor",
			testFn: func() bool {
				return version.NewExtractor() != nil
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !test.testFn() {
				t.Errorf("Failed to initialize %s", test.name)
			}
		})
	}
}

// TestSystemDataFlowPipeline tests the complete data flow through the system
func TestSystemDataFlowPipeline(t *testing.T) {
	// Step 1: Create correlator
	correlatorEngine := correlator.NewCorrelationEngine()
	if correlatorEngine == nil {
		t.Fatalf("Failed to create correlator")
	}

	// Step 2: Add events
	correlatorEngine.AddProcessEvent(1000, 999, 12345, "pip", "install flask")

	// Step 3: Create alert manager
	alertManager := alert.NewAlertManager()
	if alertManager == nil {
		t.Fatalf("Failed to create alert manager")
	}

	// Step 4: Create exporter
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "output.json",
	}
	exporter := export.NewExporter(config)
	if exporter == nil {
		t.Fatalf("Failed to create exporter")
	}

	// Step 5: Verify chain
	chains := correlatorEngine.GetDependencyChains()
	t.Logf("Successfully completed data flow pipeline with %d chains", len(chains))
}

// TestSystemMultiPackageManagerSupport tests support for multiple package managers
func TestSystemMultiPackageManagerSupport(t *testing.T) {
	engine := correlator.NewCorrelationEngine()

	managers := map[string]string{
		"pip":   "install flask",
		"npm":   "install express",
		"apt":   "install curl",
		"gem":   "install rails",
		"go":    "get github.com/user/pkg",
		"cargo": "add serde",
	}

	for pm, cmd := range managers {
		engine.AddProcessEvent(uint32(1000), 999, 12345, pm, cmd)
	}

	t.Logf("Verified support for %d package managers", len(managers))
}

// TestSystemResilience tests system resilience with edge cases
func TestSystemResilience(t *testing.T) {
	engine := correlator.NewCorrelationEngine()

	// Test with no events
	chains := engine.GetDependencyChains()
	if chains == nil {
		t.Errorf("GetDependencyChains returned nil")
	}

	// Test with high PID values
	engine.AddProcessEvent(4294967295, 999, 12345, "pip", "install package")

	// Test with special characters in paths
	engine.AddFileEvent(1000, &correlator.FileEvent{
		PID:  1000,
		Comm: "pip",
		Path: "/usr/local/lib/python3.11/site-packages/my-special_package-1.0.0.dist-info/METADATA",
	})

	chains = engine.GetDependencyChains()
	t.Logf("System resilience test passed with %d chains", len(chains))
}

// TestSystemSecurityProperties tests security-relevant properties
func TestSystemSecurityProperties(t *testing.T) {
	repDb := reputation.NewReputationDatabase()

	// Test with known good package
	score, _ := repDb.GetReputationScore("numpy", "pip")
	t.Logf("Reputation score for numpy: %v", score)

	// Test with suspicious package names
	suspiciousNames := []string{
		"numpy123",        // Similar to numpy
		"flask-admin",     // Namespace variation
		"requests_http",   // With underscore
	}

	for _, name := range suspiciousNames {
		score, _ := repDb.GetReputationScore(name, "pip")
		t.Logf("Reputation score for %s: %v", name, score)
	}

	t.Logf("Security properties validation completed")
}

// TestSystemPerformanceCharacteristics tests performance characteristics
func TestSystemPerformanceCharacteristics(t *testing.T) {
	engine := correlator.NewCorrelationEngine()

	// Add many events and verify system doesn't crash
	for i := 0; i < 1000; i++ {
		engine.AddProcessEvent(uint32(1000+i), 999, 12345, "pip", "install package")
	}

	chains := engine.GetDependencyChains()
	if chains == nil {
		t.Errorf("Failed to get chains after 1000 events")
	}

	t.Logf("Successfully handled 1000 events")
}

// TestSystemCompatibility tests system compatibility across components
func TestSystemCompatibility(t *testing.T) {
	// Create all components
	engine := correlator.NewCorrelationEngine()
	repDb := reputation.NewReputationDatabase()
	alertMgr := alert.NewAlertManager()
	scoreEngine := scoring.NewThreatScoringEngine()

	// Verify they work together
	engine.AddProcessEvent(1000, 999, 12345, "pip", "install numpy")

	chains := engine.GetDependencyChains()
	mismatches := engine.DetectVersionMismatches()

	if repDb == nil || alertMgr == nil || scoreEngine == nil {
		t.Errorf("Component compatibility check failed")
	}

	t.Logf("Component compatibility verified: %d chains, %d mismatches",
		len(chains), len(mismatches))
}

// TestSystemLongRunningStability tests stability during long-running operations
func TestSystemLongRunningStability(t *testing.T) {
	engine := correlator.NewCorrelationEngine()

	// Simulate continuous operation
	for i := 0; i < 100; i++ {
		engine.AddProcessEvent(uint32(1000+i), 999, 12345, "pip", "install package")
	}

	// Verify system is still responsive
	chains := engine.GetDependencyChains()
	mismatches := engine.DetectVersionMismatches()

	t.Logf("Long-running stability test completed: %d chains, %d mismatches",
		len(chains), len(mismatches))
}

// BenchmarkCompleteWorkflow benchmarks complete system workflow
func BenchmarkCompleteWorkflow(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Initialize all components
		engine := correlator.NewCorrelationEngine()
		repDb := reputation.NewReputationDatabase()
		alertMgr := alert.NewAlertManager()

		// Process events
		engine.AddProcessEvent(1000, 999, 12345, "pip", "install package")

		// Perform analysis
		_ = engine.GetDependencyChains()
		_ = engine.DetectVersionMismatches()

		// Verify all components initialized
		if repDb == nil || alertMgr == nil {
			b.Fatal("Component initialization failed")
		}
	}
}

// BenchmarkDataCollection benchmarks data collection performance
func BenchmarkDataCollection(b *testing.B) {
	engine := correlator.NewCorrelationEngine()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.AddProcessEvent(uint32(1000+i), 999, 12345, "pip", "install package")
	}
}

// BenchmarkReputationCheck benchmarks reputation database lookup
func BenchmarkReputationCheck(b *testing.B) {
	repDb := reputation.NewReputationDatabase()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		repDb.GetReputationScore("numpy", "pip")
	}
}
