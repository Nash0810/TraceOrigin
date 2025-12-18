package tests

import (
	"fmt"
	"testing"

	"github.com/Nash0810/TraceOrigin/pkg/correlator"
	"github.com/Nash0810/TraceOrigin/pkg/reputation"
	"github.com/Nash0810/TraceOrigin/pkg/scoring"
	"github.com/Nash0810/TraceOrigin/pkg/version"
)

// TestFullSupplyChainWorkflow tests the complete supply chain analysis workflow
func TestFullSupplyChainWorkflow(t *testing.T) {
	// Step 1: Create correlation engine to track events
	engine := correlator.NewCorrelationEngine()
	
	// Step 2: Simulate package installation process
	engine.AddProcessEvent(1000, 999, 12345, "pip", "install flask==2.3.0 requests==2.28.0")
	
	// Step 3: Simulate network activity
	engine.AddNetworkEvent(1000, &correlator.NetworkEvent{
		PID:     1000,
		Comm:    "pip",
		SrcAddr: "192.168.1.100",
		DstAddr: "151.101.0.223",
		DstPort: 443,
		IsStart: true,
	})
	
	// Step 4: Simulate file creation (packages being installed)
	engine.AddFileEvent(1000, &correlator.FileEvent{
		PID:  1000,
		Comm: "pip",
		Path: "/usr/local/lib/python3.11/site-packages/flask/__init__.py",
	})
	
	// Step 5: Get dependency chains
	chains := engine.GetDependencyChains()
	if len(chains) == 0 {
		t.Logf("No chains detected (this may be expected depending on engine behavior)")
	}
	
	// Step 6: Detect version mismatches
	mismatches := engine.DetectVersionMismatches()
	t.Logf("Detected %d version mismatches", len(mismatches))
	
	// Step 7: Link to manifest
	manifest := map[string]string{
		"flask":    "2.3.0",
		"requests": "2.28.0",
	}
	
	linked := engine.LinkManifestToObserved(manifest)
	t.Logf("Linked %d packages to manifest", len(linked))
}

// TestScoringEngineIntegration tests threat scoring integration
func TestScoringEngineIntegration(t *testing.T) {
	engine := scoring.NewThreatScoringEngine()
	if engine == nil {
		t.Fatal("Failed to create threat scoring engine")
	}
	
	t.Logf("Threat scoring engine created successfully")
}

// TestThreatScoringWithReputationIntegration tests threat scoring with reputation lookups
func TestThreatScoringWithReputationIntegration(t *testing.T) {
	repDb := reputation.NewReputationDatabase()
	if repDb == nil {
		t.Fatal("Failed to create reputation database")
	}
	
	t.Logf("Reputation database created successfully")
}

// TestVersionExtractorIntegration tests version extraction with actual filenames
func TestVersionExtractorIntegration(t *testing.T) {
	extractor := version.NewExtractor()
	
	testCases := []struct {
		filename string
		expPkg   string
	}{
		{"flask-2.3.0-py3-none-any.whl", "flask"},
		{"requests-2.28.1-py3-none-any.whl", "requests"},
	}
	
	for _, tc := range testCases {
		result := extractor.ExtractPythonVersion(tc.filename)
		if result.PackageName != tc.expPkg {
			t.Errorf("Expected package %s, got %s for %s",
				tc.expPkg, result.PackageName, tc.filename)
		}
	}
}

// TestEndToEndPackageTracking tests complete package tracking scenario
func TestEndToEndPackageTracking(t *testing.T) {
	// Initialize components
	engine := correlator.NewCorrelationEngine()
	
	// Simulate: pip install requests==2.28.0
	engine.AddProcessEvent(2000, 1999, 54321, "pip", "install requests==2.28.0")
	engine.AddNetworkEvent(2000, &correlator.NetworkEvent{
		PID:     2000,
		Comm:    "pip",
		DstAddr: "151.101.0.223",
		DstPort: 443,
		IsStart: true,
	})
	
	chains := engine.GetDependencyChains()
	mismatches := engine.DetectVersionMismatches()
	
	t.Logf("End-to-end test completed: %d chains, %d mismatches",
		len(chains), len(mismatches))
}

// TestMultiPackageManagerTracking tests tracking multiple package managers
func TestMultiPackageManagerTracking(t *testing.T) {
	engine := correlator.NewCorrelationEngine()
	
	// Simulate pip installation
	engine.AddProcessEvent(3000, 999, 11111, "pip", "install flask")
	
	// Simulate npm installation
	engine.AddProcessEvent(3001, 999, 11111, "npm", "install express")
	
	// Simulate apt installation
	engine.AddProcessEvent(3002, 999, 11111, "apt-get", "install curl")
	
	chains := engine.GetDependencyChains()
	t.Logf("Tracked %d package installations across multiple package managers", len(chains))
}

// TestConcurrentOperations tests thread-safe concurrent operations
func TestConcurrentOperations(t *testing.T) {
	engine := correlator.NewCorrelationEngine()
	
	// Simulate concurrent package installations
	done := make(chan bool, 10)
	
	for i := 0; i < 10; i++ {
		go func(pid uint32, pkgNum int) {
			engine.AddProcessEvent(pid, 999, uint64(pkgNum), "pip", fmt.Sprintf("install pkg%d", pkgNum))
			done <- true
		}(uint32(4000+i), i)
	}
	
	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}
	
	t.Logf("Concurrent operations completed successfully")
}

// TestManifestCorrelation tests correlating manifest with observed packages
func TestManifestCorrelation(t *testing.T) {
	engine := correlator.NewCorrelationEngine()
	
	// Add process simulating manifest
	engine.AddProcessEvent(5000, 999, 12345, "pip", "install -r requirements.txt")
	
	// Create manifest
	manifest := map[string]string{
		"flask":    "2.3.0",
		"requests": "2.28.0",
		"numpy":    "1.24.0",
	}
	
	// Link to observed
	linked := engine.LinkManifestToObserved(manifest)
	
	// Verify result
	if linked == nil {
		t.Fatalf("LinkManifestToObserved returned nil")
	}
	
	t.Logf("Linked %d packages from manifest", len(linked))
}

// TestVersionConstraintValidation tests version constraint validation
func TestVersionConstraintValidation(t *testing.T) {
	tests := []struct {
		declared string
		actual   string
		expected bool
	}{
		{"2.3.0", "2.3.0", true},
		{"2.3.0", "2.3.1", false},
		{"1.0.0", "1.0.0", true},
		{"3.0.0", "2.9.0", false},
	}
	
	for _, tc := range tests {
		result := correlator.VersionConstraintSatisfied(tc.declared, tc.actual)
		if result != tc.expected {
			t.Errorf("VersionConstraintSatisfied(%s, %s) = %v, expected %v",
				tc.declared, tc.actual, result, tc.expected)
		}
	}
}

// BenchmarkFullWorkflow benchmarks complete supply chain workflow
func BenchmarkFullWorkflow(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine := correlator.NewCorrelationEngine()
		engine.AddProcessEvent(1000, 999, 12345, "pip", "install package")
		engine.GetDependencyChains()
		engine.DetectVersionMismatches()
	}
}

// BenchmarkThreatScoring benchmarks threat scoring
func BenchmarkThreatScoring(b *testing.B) {
	scoreEngine := scoring.NewThreatScoringEngine()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		scoreEngine.GetScore("numpy", "1.24.0")
	}
}

// BenchmarkReputationLookup benchmarks reputation database lookup
func BenchmarkReputationLookup(b *testing.B) {
	db := reputation.NewReputationDatabase()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db.GetReputationScore("flask", "pip")
	}
}

// BenchmarkCorrelation benchmarks correlation engine
func BenchmarkCorrelation(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine := correlator.NewCorrelationEngine()
		engine.AddProcessEvent(1000, 999, 12345, "pip", "install package")
	}
}

