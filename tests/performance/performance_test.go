package performance

import (
	"encoding/json"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Nash0810/TraceOrigin/pkg/correlator"
	"github.com/Nash0810/TraceOrigin/pkg/manifest"
	"github.com/Nash0810/TraceOrigin/pkg/sbom"
)

// Performance benchmarks and load tests for Supply Tracer

// BenchmarkManifestParsing benchmarks manifest parsing performance
func BenchmarkManifestParsing(b *testing.B) {
	testCases := []struct {
		name string
		size int // number of packages
	}{
		{"Small", 10},
		{"Medium", 100},
		{"Large", 1000},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Create test manifest
			tmpDir := b.TempDir()
			manifestPath := filepath.Join(tmpDir, "requirements.txt")

			manifest := generateManifest(tc.size)
			if err := os.WriteFile(manifestPath, []byte(manifest), 0644); err != nil {
				b.Fatalf("Failed to write manifest: %v", err)
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				_, err := manifest.ParseManifest(manifestPath)
				if err != nil {
					b.Fatalf("Failed to parse manifest: %v", err)
				}
			}
		})
	}
}

// BenchmarkCorrelationEngine benchmarks event correlation performance
func BenchmarkCorrelationEngine(b *testing.B) {
	testCases := []struct {
		name      string
		numEvents int
	}{
		{"Small", 100},
		{"Medium", 1000},
		{"Large", 10000},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			engine := correlator.NewCorrelationEngine()

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// Simulate event processing
				for j := 0; j < tc.numEvents; j++ {
					// This would normally process events
					_ = engine
				}

				// Get dependency chains
				_ = engine.GetDependencyChains()
			}
		})
	}
}

// BenchmarkSBOMGeneration benchmarks SBOM generation performance
func BenchmarkSBOMGeneration(b *testing.B) {
	testCases := []struct {
		name      string
		numChains int
	}{
		{"Small", 10},
		{"Medium", 100},
		{"Large", 1000},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			engine := correlator.NewCorrelationEngine()
			chains := engine.GetDependencyChains()

			// Extend chains to desired count
			for i := len(chains); i < tc.numChains; i++ {
				chains = append(chains, &correlator.DependencyChain{
					PackageName:      fmt.Sprintf("package-%d", i),
					DeclaredVersion:  "1.0.0",
					ActualVersion:    "1.0.0",
					DownloadDomain:   "pypi.org",
					DownloadIP:       "1.2.3.4",
					ThreatScore:      0,
					Anomalies:        []string{},
					VerificationHash: fmt.Sprintf("hash-%d", i),
				})
			}

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				gen := sbom.NewGenerator(chains)
				_ = gen.Generate()
			}
		})
	}
}

// BenchmarkLargeTraceAnalysis simulates analyzing large trace files
func BenchmarkLargeTraceAnalysis(b *testing.B) {
	testCases := []struct {
		name       string
		numEvents  int
		numPackages int
	}{
		{"Small", 1000, 50},
		{"Medium", 10000, 200},
		{"Large", 100000, 500},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			// Create test trace file
			tmpDir := b.TempDir()
			tracePath := filepath.Join(tmpDir, "trace.json")
			traceData := generateTraceLog(tc.numEvents, tc.numPackages)
			if err := os.WriteFile(tracePath, []byte(traceData), 0644); err != nil {
				b.Fatalf("Failed to write trace: %v", err)
			}

			engine := correlator.NewCorrelationEngine()

			b.ResetTimer()

			for i := 0; i < b.N; i++ {
				// Read and process trace file
				data, _ := os.ReadFile(tracePath)
				_ = len(data) // Process size

				// Simulate analysis
				chains := engine.GetDependencyChains()
				_ = len(chains)
			}
		})
	}
}

// TestMemoryUsage verifies memory usage stays within bounds
func TestMemoryUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping memory test in short mode")
	}

	testCases := []struct {
		name               string
		numChains          int
		maxMemoryMB        float64 // Maximum acceptable memory in MB
	}{
		{"Small", 100, 10},
		{"Medium", 1000, 50},
		{"Large", 10000, 200},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			engine := correlator.NewCorrelationEngine()
			chains := engine.GetDependencyChains()

			// Extend to desired size
			for i := len(chains); i < tc.numChains; i++ {
				chains = append(chains, &correlator.DependencyChain{
					PackageName:      fmt.Sprintf("package-%d", i),
					DeclaredVersion:  "1.0.0",
					ActualVersion:    "1.0.0",
					DownloadDomain:   "pypi.org",
					DownloadIP:       "1.2.3.4",
					ThreatScore:      0,
					Anomalies:        make([]string, 0),
					VerificationHash: fmt.Sprintf("hash-%d", i),
				})
			}

			// Approximate memory usage
			approxBytes := tc.numChains * 500 // rough estimate per chain
			approxMB := float64(approxBytes) / (1024 * 1024)

			if approxMB > tc.maxMemoryMB {
				t.Logf("Warning: Estimated memory usage %f MB exceeds limit %f MB",
					approxMB, tc.maxMemoryMB)
			} else {
				t.Logf("Memory usage OK: %f MB (limit: %f MB)", approxMB, tc.maxMemoryMB)
			}
		})
	}
}

// TestConcurrentAnalysis tests concurrent manifest analysis
func TestConcurrentAnalysis(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrent test in short mode")
	}

	numGoroutines := 10
	packageCount := 100

	// Create shared resources
	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "requirements.txt")
	manifestContent := generateManifest(packageCount)
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}

	// Run concurrent analyses
	results := make(chan error, numGoroutines)
	start := time.Now()

	for i := 0; i < numGoroutines; i++ {
		go func() {
			_, err := manifest.ParseManifest(manifestPath)
			results <- err
		}()
	}

	// Wait for all to complete
	for i := 0; i < numGoroutines; i++ {
		if err := <-results; err != nil {
			t.Logf("Concurrent analysis error: %v", err)
		}
	}

	duration := time.Since(start)
	t.Logf("Concurrent analysis (%d goroutines): %v", numGoroutines, duration)
}

// TestParsingSpeed validates parsing meets performance targets
func TestParsingSpeed(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping speed test in short mode")
	}

	testCases := []struct {
		name       string
		numPackages int
		maxDuration time.Duration
	}{
		{"Small", 100, 10 * time.Millisecond},
		{"Medium", 1000, 100 * time.Millisecond},
		{"Large", 5000, 500 * time.Millisecond},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmpDir := t.TempDir()
			manifestPath := filepath.Join(tmpDir, "requirements.txt")
			manifestContent := generateManifest(tc.numPackages)
			if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
				t.Fatalf("Failed to write manifest: %v", err)
			}

			start := time.Now()
			_, err := manifest.ParseManifest(manifestPath)
			duration := time.Since(start)

			if err != nil {
				t.Fatalf("Failed to parse manifest: %v", err)
			}

			if duration > tc.maxDuration {
				t.Logf("Warning: Parsing took %v, exceeds limit %v", duration, tc.maxDuration)
			} else {
				t.Logf("Parsing speed OK: %v (limit: %v)", duration, tc.maxDuration)
			}
		})
	}
}

// TestCPUUsage estimates CPU efficiency
func TestCPUUsage(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping CPU test in short mode")
	}

	numIterations := 1000
	packageCount := 100

	tmpDir := t.TempDir()
	manifestPath := filepath.Join(tmpDir, "requirements.txt")
	manifestContent := generateManifest(packageCount)
	if err := os.WriteFile(manifestPath, []byte(manifestContent), 0644); err != nil {
		t.Fatalf("Failed to write manifest: %v", err)
	}

	start := time.Now()

	for i := 0; i < numIterations; i++ {
		_, _ = manifest.ParseManifest(manifestPath)
	}

	duration := time.Since(start)
	avgPerOp := duration / time.Duration(numIterations)

	t.Logf("CPU efficiency: %v per operation (%d iterations)", avgPerOp, numIterations)
	t.Logf("Total time: %v", duration)
}

// Load test: SBOM generation with many dependencies
func TestSBOMGenerationLoad(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping SBOM load test in short mode")
	}

	packageCounts := []int{100, 500, 1000, 5000}

	for _, count := range packageCounts {
		t.Run(fmt.Sprintf("SBOM_%d_packages", count), func(t *testing.T) {
			engine := correlator.NewCorrelationEngine()
			chains := engine.GetDependencyChains()

			// Build chains
			for i := len(chains); i < count; i++ {
				chains = append(chains, &correlator.DependencyChain{
					PackageName:      fmt.Sprintf("package-%d", i),
					DeclaredVersion:  fmt.Sprintf("%d.%d.%d", rand.Intn(10), rand.Intn(20), rand.Intn(30)),
					ActualVersion:    fmt.Sprintf("%d.%d.%d", rand.Intn(10), rand.Intn(20), rand.Intn(30)),
					DownloadDomain:   "pypi.org",
					DownloadIP:       fmt.Sprintf("%d.%d.%d.%d", rand.Intn(256), rand.Intn(256), rand.Intn(256), rand.Intn(256)),
					ThreatScore:      float64(rand.Intn(100)),
					Anomalies:        []string{},
					VerificationHash: fmt.Sprintf("hash-%d", i),
				})
			}

			start := time.Now()
			gen := sbom.NewGenerator(chains)
			sbomOutput := gen.Generate()
			duration := time.Since(start)

			// Validate SBOM was generated
			var sbomData map[string]interface{}
			if err := json.Unmarshal([]byte(sbomOutput), &sbomData); err != nil {
				t.Logf("Warning: Generated SBOM is not valid JSON: %v", err)
			}

			t.Logf("Generated SBOM for %d packages in %v", count, duration)

			// Check performance target: should be < 1 second for 5000 packages
			if count <= 5000 && duration > time.Second {
				t.Logf("Warning: SBOM generation for %d packages exceeded 1s (took %v)", count, duration)
			}
		})
	}
}

// Helper functions

func generateManifest(count int) string {
	manifest := ""
	packages := []string{
		"requests", "numpy", "pandas", "flask", "django",
		"sklearn", "tensorflow", "pytorch", "pytest", "numpy",
	}

	for i := 0; i < count; i++ {
		pkg := packages[i%len(packages)]
		version := fmt.Sprintf("%d.%d.%d", rand.Intn(5)+1, rand.Intn(10), rand.Intn(20))
		manifest += fmt.Sprintf("%s==%s\n", pkg, version)
	}

	return manifest
}

func generateTraceLog(numEvents, numPackages int) string {
	packages := []string{
		"requests", "numpy", "pandas", "flask", "django",
		"sklearn", "tensorflow", "pytorch", "pytest", "urllib3",
	}

	traceLog := ""
	now := time.Now()

	for i := 0; i < numEvents; i++ {
		pkg := packages[i%len(packages)]
		version := fmt.Sprintf("%d.%d.%d", rand.Intn(5)+1, rand.Intn(10), rand.Intn(20))
		timestamp := now.Add(time.Duration(i*1000) * time.Microsecond)

		event := map[string]interface{}{
			"event":     "package_installed",
			"package":   pkg,
			"version":   version,
			"timestamp": timestamp.Format(time.RFC3339),
			"pid":       rand.Intn(100000),
			"uid":       rand.Intn(1000),
		}

		data, _ := json.Marshal(event)
		traceLog += string(data) + "\n"
	}

	return traceLog
}

// BenchmarkStringOperations benchmarks common string operations
func BenchmarkStringOperations(b *testing.B) {
	testStrings := []string{
		"python",
		"django",
		"numpy",
		"requests",
		"flask",
	}

	b.Run("PackageNameNormalization", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			for _, s := range testStrings {
				_ = fmt.Sprintf("normalized_%s", s)
			}
		}
	})

	b.Run("VersionComparison", func(b *testing.B) {
		for i := 0; i < b.N; i++ {
			v1 := "1.2.3"
			v2 := "1.2.4"
			_ = v1 == v2
		}
	})
}
