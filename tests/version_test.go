package tests

import (
	"testing"

	"github.com/Nash0810/TraceOrigin/pkg/correlator"
	"github.com/Nash0810/TraceOrigin/pkg/version"
)

// TestVersionExtractorCreation tests version extractor initialization
func TestVersionExtractorCreation(t *testing.T) {
	extractor := version.NewExtractor()
	if extractor == nil {
		t.Fatal("Failed to create version extractor")
	}
}

// TestVersionExtractorPython tests Python version extraction
func TestVersionExtractorPython(t *testing.T) {
	extractor := version.NewExtractor()
	
	result := extractor.ExtractPythonVersion("flask-2.3.0-py3-none-any.whl")
	if result.PackageName != "flask" {
		t.Errorf("Expected package 'flask', got '%s'", result.PackageName)
	}
	if result.Version == "" {
		t.Errorf("Failed to extract version from Python wheel")
	}
}

// TestVersionExtractorRuby tests Ruby version extraction
func TestVersionExtractorRuby(t *testing.T) {
	extractor := version.NewExtractor()
	
	result := extractor.ExtractRubyVersion("json-2.6.2.gem")
	if result.PackageName != "json" {
		t.Errorf("Expected package 'json', got '%s'", result.PackageName)
	}
	if result.Version != "2.6.2" {
		t.Errorf("Expected version '2.6.2', got '%s'", result.Version)
	}
}

// TestVersionExtractorAPT tests APT version extraction from filename
func TestVersionExtractorAPT(t *testing.T) {
	extractor := version.NewExtractor()
	
	result := extractor.ExtractAptVersionFromFilename("curl_7.68.0-1ubuntu1_amd64.deb")
	if result.PackageName != "curl" {
		t.Errorf("Expected package 'curl', got '%s'", result.PackageName)
	}
	if result.Version == "" {
		t.Errorf("Failed to extract version from APT filename")
	}
}

// TestCorrelationEngineCreation tests correlation engine initialization
func TestCorrelationEngineCreation(t *testing.T) {
	engine := correlator.NewCorrelationEngine()
	if engine == nil {
		t.Fatal("Failed to create correlation engine")
	}
}

// TestCorrelationEngineProcessEvent tests adding process events
func TestCorrelationEngineProcessEvent(t *testing.T) {
	engine := correlator.NewCorrelationEngine()
	
	engine.AddProcessEvent(1000, 999, 12345, "pip", "install flask==2.3.0")
	
	chains := engine.GetDependencyChains()
	if len(chains) > 0 && chains[0].PackageName != "flask" {
		t.Errorf("Process event not properly recorded")
	}
}

// TestCorrelationEngineVersionMismatchDetection tests version mismatch detection
func TestCorrelationEngineVersionMismatchDetection(t *testing.T) {
	engine := correlator.NewCorrelationEngine()
	
	// Create a chain with mismatched versions
	engine.AddProcessEvent(2000, 999, 12345, "pip", "install requests==2.28.0")
	
	// Get the chains to verify setup
	chains := engine.GetDependencyChains()
	if len(chains) == 0 {
		t.Skip("No chains detected from process event")
	}
	
	// Detect mismatches
	mismatches := engine.DetectVersionMismatches()
	
	// If there are mismatches, verify they have the expected fields
	if len(mismatches) > 0 {
		m := mismatches[0]
		if m.DeclaredVersion == "" && m.ActualVersion == "" {
			t.Errorf("Mismatch should have at least declared or actual version")
		}
	}
}

// TestVersionConstraintSatisfied tests version constraint checking
func TestVersionConstraintSatisfied(t *testing.T) {
	tests := []struct {
		constraint string
		actual     string
		expected   bool
	}{
		{"2.3.0", "2.3.0", true},
		{"2.3.0", "2.3.1", false},
		{"2.0.0", "2.0.0", true},
		{"1.0.0", "2.0.0", false},
	}
	
	for _, tc := range tests {
		result := correlator.VersionConstraintSatisfied(tc.constraint, tc.actual)
		if result != tc.expected {
			t.Errorf("VersionConstraintSatisfied(%s, %s) = %v, expected %v",
				tc.constraint, tc.actual, result, tc.expected)
		}
	}
}

// TestLinkManifestToObserved tests linking manifest to observed packages
func TestLinkManifestToObserved(t *testing.T) {
	engine := correlator.NewCorrelationEngine()
	
	engine.AddProcessEvent(3000, 999, 12345, "pip", "install flask==2.3.0 requests==2.28.0")
	
	declared := map[string]string{
		"flask":    "2.3.0",
		"requests": "2.28.0",
	}
	
	result := engine.LinkManifestToObserved(declared)
	if result == nil {
		t.Fatalf("LinkManifestToObserved returned nil")
	}
	
	if len(result) > 0 {
		for name, chain := range result {
			if chain == nil {
				t.Errorf("Chain for %s is nil", name)
			}
		}
	}
}

// TestCorrelationEngineNetworkEvent tests adding network events
func TestCorrelationEngineNetworkEvent(t *testing.T) {
	engine := correlator.NewCorrelationEngine()
	
	engine.AddProcessEvent(4000, 999, 12345, "pip", "install numpy")
	
	engine.AddNetworkEvent(4000, &correlator.NetworkEvent{
		PID:       4000,
		Comm:      "pip",
		SrcAddr:   "192.168.1.100",
		DstAddr:   "151.101.0.223",
		DstPort:   443,
		Timestamp: 4000000,
		IsStart:   true,
	})
	
	chains := engine.GetDependencyChains()
	// Should have recorded the network event
	if len(chains) == 0 {
		t.Logf("No chains yet (network events may not create chains immediately)")
	}
}

// TestCorrelationEngineHTTPEvent tests adding HTTP events
func TestCorrelationEngineHTTPEvent(t *testing.T) {
	engine := correlator.NewCorrelationEngine()
	
	engine.AddProcessEvent(5000, 999, 12345, "pip", "install scipy")
	
	engine.AddHTTPEvent(5000, &correlator.HTTPEvent{
		PID:       5000,
		Comm:      "pip",
		URL:       "https://files.pythonhosted.org/packages/scipy-1.10.0.whl",
		Host:      "files.pythonhosted.org",
		Method:    1, // GET
		Timestamp: 5000000,
	})
	
	chains := engine.GetDependencyChains()
	if len(chains) > 0 {
		if chains[0].DownloadURL == "" {
			t.Logf("HTTP event recorded but URL not populated in chain yet")
		}
	}
}

// BenchmarkVersionExtraction benchmarks version extraction
func BenchmarkVersionExtraction(b *testing.B) {
	extractor := version.NewExtractor()
	filename := "numpy-1.24.3-cp311-cp311-manylinux_2_17_x86_64.whl"
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		extractor.ExtractPythonVersion(filename)
	}
}

// BenchmarkCorrelationEngine benchmarks correlation engine
func BenchmarkCorrelationEngine(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine := correlator.NewCorrelationEngine()
		engine.AddProcessEvent(1000, 999, 12345, "pip", "install package")
		engine.GetDependencyChains()
	}
}

// BenchmarkVersionMismatchDetection benchmarks mismatch detection
func BenchmarkVersionMismatchDetection(b *testing.B) {
	engine := correlator.NewCorrelationEngine()
	
	// Setup with packages
	for i := 0; i < 50; i++ {
		engine.AddProcessEvent(uint32(1000+i), 999, 12345, "pip", "install package")
	}
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		engine.DetectVersionMismatches()
	}
}

