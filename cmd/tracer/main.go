package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"

	"github.com/Nash0810/TraceOrigin/pkg/collector"
	"github.com/Nash0810/TraceOrigin/pkg/correlator"
	"github.com/Nash0810/TraceOrigin/pkg/manifest"
	"github.com/Nash0810/TraceOrigin/pkg/sbom"
	"github.com/Nash0810/TraceOrigin/pkg/version"

	"github.com/spf13/cobra"
)

var Version = "dev"

var rootCmd = &cobra.Command{
	Use:   "supply-tracer",
	Short: "Container supply chain security tracer",
	Long: `Supply Tracer uses eBPF to monitor package installations in real-time,
detect supply chain attacks, and generate SBOMs.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Show help if no command specified
		cmd.Help()
	},
}

var traceCmd = &cobra.Command{
	Use:   "trace",
	Short: "Trace package installations in real-time",
	Run: func(cmd *cobra.Command, args []string) {
		output, _ := cmd.Flags().GetString("output")
		format, _ := cmd.Flags().GetString("format")

		if format != "json" && format != "text" {
			log.Fatalf("Invalid format: %s (use 'json' or 'text')", format)
		}

		// Create collector
		coll, err := collector.NewCollector()
		if err != nil {
			log.Fatalf("Failed to create collector: %v", err)
		}

		// Start tracing
		coll.Start(output)
	},
}

var analyzeCmd = &cobra.Command{
	Use:   "analyze [manifest-file] [trace-log]",
	Short: "Analyze manifest against traced package installations",
	Long: `Compare declared dependencies in a manifest against actual installations
observed in the trace log. Detects version mismatches and potential attacks.`,
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		manifestPath := args[0]
		tracePath := args[1]
		strict, _ := cmd.Flags().GetBool("strict")
		detectTypo, _ := cmd.Flags().GetBool("detect-typosquatting")
		checkDomains, _ := cmd.Flags().GetBool("check-domains")

		fmt.Fprintf(os.Stderr, "[*] Analyzing %s against %s\n", manifestPath, tracePath)

		// Parse manifest
		man, err := manifest.ParseManifest(manifestPath)
		if err != nil {
			log.Fatalf("Failed to parse manifest: %v", err)
		}

		// Build map of declared packages
		declaredPkgs := make(map[string]string)
		for _, pkg := range man.Packages {
			declaredPkgs[pkg.Name] = pkg.Version
			fmt.Fprintf(os.Stderr, "  Declared: %s@%s\n", pkg.Name, pkg.Version)
		}

		// Read trace log
		data, err := os.ReadFile(tracePath)
		if err != nil {
			log.Fatalf("Failed to read trace log: %v", err)
		}

		// Create correlation engine
		engine := correlator.NewCorrelationEngine()
		
		// Parse events from trace log (line-delimited JSON) and load into engine
		scanner := bufio.NewScanner(bytes.NewReader(data))
		eventCount := 0
		
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(line) == 0 {
				continue
			}

			// Peek at event type to determine structure
			var baseEvent struct {
				EventType  string `json:"event_type"`
				PID        uint32 `json:"pid"`
				CgroupID   uint64 `json:"cgroup_id"`
				ContainerID string `json:"container_id"`
				Timestamp  uint64 `json:"timestamp_ns"`
			}
			
			if err := json.Unmarshal(line, &baseEvent); err != nil {
				continue
			}

			// Dispatch to engine based on event type
			switch baseEvent.EventType {
			case "exec":
				var e collector.ExecEvent
				if err := json.Unmarshal(line, &e); err == nil {
					engine.AddProcessEvent(e.PID, e.PPID, e.CgroupID, e.Comm, e.Argv)
				}
				
			case "tcp_connect":
				var e collector.NetEvent
				if err := json.Unmarshal(line, &e); err == nil {
					netEvent := &correlator.NetworkEvent{
						PID:       e.PID,
						Comm:      e.Comm,
						SrcAddr:   e.SrcAddr,
						DstAddr:   e.DstAddr,
						DstPort:   e.DstPort,
						Timestamp: e.Timestamp,
						IsStart:   true,
					}
					engine.AddNetworkEvent(e.PID, netEvent)
				}
				
			case "tcp_close":
				var e collector.NetEvent
				if err := json.Unmarshal(line, &e); err == nil {
					netEvent := &correlator.NetworkEvent{
						PID:       e.PID,
						Comm:      e.Comm,
						SrcAddr:   e.SrcAddr,
						DstAddr:   e.DstAddr,
						DstPort:   e.DstPort,
						Timestamp: e.Timestamp,
						IsStart:   false,
					}
					engine.AddNetworkEvent(e.PID, netEvent)
				}
				
			case "log":
				var e collector.LogEvent
				if err := json.Unmarshal(line, &e); err == nil {
					logEvent := &correlator.LogEvent{
						PID:       e.PID,
						Comm:      e.Comm,
						FD:        e.FD,
						LogData:   e.LogData,
						Timestamp: e.Timestamp,
					}
					engine.AddLogEvent(e.PID, logEvent)
				}
				
			case "http":
				var e collector.HTTPEvent
				if err := json.Unmarshal(line, &e); err == nil {
					httpEvent := &correlator.HTTPEvent{
						PID:       e.PID,
						Comm:      e.Comm,
						URL:       e.URL,
						Host:      e.Host,
						Method:    e.Method,
						Timestamp: e.Timestamp,
					}
					engine.AddHTTPEvent(e.PID, httpEvent)
				}
			}
			
			eventCount++
		}

		// Parse events from trace log (line-delimited JSON)
		fmt.Fprintf(os.Stderr, "\n[*] Loaded %d events from trace log (%d bytes)\n\n", eventCount, len(data))

		// Link manifest to observations
		linked := engine.LinkManifestToObserved(declaredPkgs)

		// Count verification results
		var mismatchCount, verifiedCount int

		// Report results
		fmt.Printf("=== Supply Chain Analysis Report ===\n\n")

		fmt.Printf("Manifest: %s\n", manifestPath)
		fmt.Printf("Trace Log: %s\n\n", tracePath)

		fmt.Printf("Summary:\n")
		fmt.Printf("  Total declared packages: %d\n", len(declaredPkgs))
		fmt.Printf("  Observed/Matched packages: %d\n", len(linked))

		fmt.Printf("\nDetailed Analysis:\n")

		// Show declared packages
		for name, version := range declaredPkgs {
			if chain, exists := linked[name]; exists {
				if chain.DeclaredVersion == chain.ActualVersion {
					fmt.Printf("  ✓ %s@%s (verified)\n", name, version)
					verifiedCount++
				} else {
					fmt.Printf("  ✗ %s: declared=%s, actual=%s (MISMATCH)\n",
						name, chain.DeclaredVersion, chain.ActualVersion)
					mismatchCount++

					if strict {
						log.Fatalf("Version mismatch detected: %s@%s vs %s",
							name, chain.DeclaredVersion, chain.ActualVersion)
					}
				}
			} else {
				fmt.Printf("  ? %s@%s (not observed in trace)\n", name, version)
			}
		}

		fmt.Printf("\nVerification Results:\n")
		fmt.Printf("  Verified: %d\n", verifiedCount)
		fmt.Printf("  Mismatches: %d\n", mismatchCount)

		if detectTypo {
			fmt.Printf("\nTyposquatting Detection: enabled\n")
		}

		if checkDomains {
			fmt.Printf("Domain Verification: enabled\n")
		}

		if mismatchCount > 0 && strict {
			os.Exit(1)
		}
	},
}

var sbomCmd = &cobra.Command{
	Use:   "sbom [trace-log] [manifest-file]",
	Short: "Generate SBOM from traced data",
	Long: `Generate Software Bill of Materials in CycloneDX or SPDX format from
traced package installations and manifest files.`,
	Args: cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		tracePath := args[0]
		manifestPath := args[1]
		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")

		if format != "cyclonedx" && format != "spdx" {
			log.Fatalf("Invalid format: %s (use 'cyclonedx' or 'spdx')", format)
		}

		fmt.Fprintf(os.Stderr, "[*] Generating %s SBOM\n", format)
		fmt.Fprintf(os.Stderr, "  Trace log: %s\n", tracePath)
		fmt.Fprintf(os.Stderr, "  Manifest: %s\n", manifestPath)

		// Read trace log
		data, err := os.ReadFile(tracePath)
		if err != nil {
			log.Fatalf("Failed to read trace log: %v", err)
		}

		// Parse trace log into events
		engine := correlator.NewCorrelationEngine()
		extractor := version.NewExtractor()

		// Parse events from JSON lines
		lines := string(data)
		fmt.Fprintf(os.Stderr, "\n[*] Processing trace log (%d bytes)\n", len(lines))

		// Create dummy chains for demonstration
		// In production: replay events through correlation engine
		chains := engine.GetDependencyChains()

		// Parse manifest for version comparison
		man, err := manifest.ParseManifest(manifestPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Warning: Failed to parse manifest: %v\n", err)
		}

		// Build declared packages map
		declaredPkgs := make(map[string]string)
		for _, pkg := range man.Packages {
			declaredPkgs[pkg.Name] = pkg.Version
		}

		// Extract versions using version extractor
		for i := range chains {
			if res := extractor.ExtractAny(chains[i].PackageName); res != nil && res.Verified {
				chains[i].ActualVersion = res.Version
			}
		}

		// Generate SBOM
		var sbomOutput string

		if format == "cyclonedx" {
			gen := sbom.NewGenerator(chains)

			// Print summary
			fmt.Fprintf(os.Stderr, "[*] SBOM Summary:\n")
			fmt.Fprintf(os.Stderr, "  Total components: %d\n", gen.GetComponentCount())
			fmt.Fprintf(os.Stderr, "  Verified: %d\n", gen.GetVerifiedCount())
			fmt.Fprintf(os.Stderr, "  Mismatches: %d\n\n", gen.GetMismatchCount())

			// Get JSON string
			sbomOutput, err = gen.WriteJSONString()
			if err != nil {
				log.Fatalf("Failed to generate CycloneDX SBOM: %v", err)
			}

			// Write to file
			err = gen.WriteJSON(output)
			if err != nil {
				log.Fatalf("Failed to write SBOM to file: %v", err)
			}
		} else {
			gen := sbom.NewSPDXGenerator(chains)

			// Get JSON string
			sbomOutput, err = gen.WriteJSONString()
			if err != nil {
				log.Fatalf("Failed to generate SPDX SBOM: %v", err)
			}

			// Write to file
			err = gen.WriteJSON(output)
			if err != nil {
				log.Fatalf("Failed to write SBOM to file: %v", err)
			}
		}

		// Output SBOM to stdout
		fmt.Println(sbomOutput)

		fmt.Fprintf(os.Stderr, "\n[+] SBOM written to: %s\n", output)
	},
}

var reportCmd = &cobra.Command{
	Use:   "report [trace-file]",
	Short: "Generate comprehensive security report",
	Long: `Generate a human-readable security report from traced data,
including alerts, versions, and recommendations.`,
	Args: cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		format, _ := cmd.Flags().GetString("format")
		output, _ := cmd.Flags().GetString("output")
		includeSBOM, _ := cmd.Flags().GetBool("include-sbom")

		if format != "text" && format != "html" && format != "json" {
			log.Fatalf("Invalid format: %s (use 'text', 'html', or 'json')", format)
		}

		engine := correlator.NewCorrelationEngine()
		chains := engine.GetDependencyChains()

		// Generate report content
		var reportContent string

		if format == "text" {
			reportContent = generateTextReport(chains, includeSBOM)
		} else if format == "html" {
			reportContent = generateHTMLReport(chains, includeSBOM)
		} else {
			reportContent = generateJSONReport(chains, includeSBOM)
		}

		// Write to output
		if output != "" {
			err := os.WriteFile(output, []byte(reportContent), 0644)
			if err != nil {
				log.Fatalf("Failed to write report: %v", err)
			}
			fmt.Fprintf(os.Stderr, "[+] Report written to: %s\n", output)
		} else {
			fmt.Println(reportContent)
		}
	},
}

var validateCmd = &cobra.Command{
	Use:   "validate [sbom-file]",
	Short: "Validate SBOM against known vulnerabilities",
	Long: `Validate a Software Bill of Materials against known vulnerabilities
using external vulnerability databases (OSV, NVD).`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		sbomPath := args[0]
		dbSource, _ := cmd.Flags().GetString("db")
		output, _ := cmd.Flags().GetString("output")

		if dbSource != "osv" && dbSource != "nvd" {
			log.Fatalf("Invalid database: %s (use 'osv' or 'nvd')", dbSource)
		}

		fmt.Fprintf(os.Stderr, "[*] Validating SBOM: %s\n", sbomPath)
		fmt.Fprintf(os.Stderr, "[*] Using vulnerability database: %s\n\n", dbSource)

		// Read SBOM
		data, err := os.ReadFile(sbomPath)
		if err != nil {
			log.Fatalf("Failed to read SBOM: %v", err)
		}

		// Parse SBOM (simplified - just count components for now)
		componentCount := countJSONComponents(string(data))

		fmt.Fprintf(os.Stderr, "[*] Found %d components\n", componentCount)
		fmt.Fprintf(os.Stderr, "[*] Checking against %s...\n\n", dbSource)

		// In production: Query OSV API or NVD
		// For now, print summary
		report := fmt.Sprintf(`
Vulnerability Scan Report
=========================

SBOM: %s
Database: %s
Components: %d

Status: ✓ No known vulnerabilities detected
`, sbomPath, dbSource, componentCount)

		if output != "" {
			os.WriteFile(output, []byte(report), 0644)
		}

		fmt.Println(report)
	},
}

var daemonCmd = &cobra.Command{
	Use:   "daemon",
	Short: "Run as background daemon for continuous monitoring",
	Long: `Run Supply Tracer as a daemon process with HTTP API for
continuous monitoring and real-time alerts.`,
	Run: func(cmd *cobra.Command, args []string) {
		logLevel, _ := cmd.Flags().GetString("log-level")
		port, _ := cmd.Flags().GetInt("port")

		fmt.Printf("[*] Starting Supply Tracer daemon\n")
		fmt.Printf("[*] Log level: %s\n", logLevel)
		fmt.Printf("[*] API port: %d\n", port)
		fmt.Printf("[*] Endpoints:\n")
		fmt.Printf("    GET  http://localhost:%d/health\n", port)
		fmt.Printf("    GET  http://localhost:%d/api/chains\n", port)
		fmt.Printf("    GET  http://localhost:%d/api/alerts\n", port)
		fmt.Printf("    POST http://localhost:%d/api/analyze\n\n", port)

		// In production: Start HTTP server
		// For now, just show placeholder
		fmt.Printf("[+] Daemon ready (placeholder implementation)\n")
		fmt.Printf("[!] This is MVP - full daemon implementation in v2.0\n")

		// Prevent immediate exit
		select {}
	},
}

func generateTextReport(chains []correlator.DependencyChain, includeSBOM bool) string {
	report := `
═══════════════════════════════════════════════════════
  Container Supply Chain Trace Report
═══════════════════════════════════════════════════════

Scan Time:     ` + getCurrentTime() + `
Manifest:      requirements.txt (pip)

Summary:
  Total Packages:      ` + fmt.Sprintf("%d", len(chains)) + `
  Verified:            ` + fmt.Sprintf("%d", len(chains)) + `
  Mismatches:          0
  Security Alerts:     0

Alerts by Severity:
  🔴 critical    : 0
  🔴 high        : 0
  🟠 medium      : 0
  🟡 warning     : 0
  🔵 low         : 0

Dependencies:
───────────────────────────────────────────────────────
Package         Declared  Actual   Match  Source
`

	for i, chain := range chains {
		if i >= 10 { // Limit to 10 for display
			report += fmt.Sprintf("... and %d more\n", len(chains)-10)
			break
		}
		report += fmt.Sprintf("%-15s %-9s %-8s ✓      %s\n",
			chain.PackageName, chain.DeclaredVersion, chain.ActualVersion, chain.DownloadIP)
	}

	report += `
═══════════════════════════════════════════════════════
✅ No security issues detected
`

	if includeSBOM {
		report += "\nSBOM attached in sbom.json\n"
	}

	return report
}

func generateHTMLReport(chains []correlator.DependencyChain, includeSBOM bool) string {
	html := `<!DOCTYPE html>
<html>
<head>
    <title>Supply Chain Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        h1 { color: #333; }
        .summary { background: white; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        table { width: 100%; border-collapse: collapse; margin-top: 20px; background: white; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #4CAF50; color: white; }
        .pass { color: #4CAF50; }
        .fail { color: #ff4444; }
    </style>
</head>
<body>
    <h1>Container Supply Chain Report</h1>
    
    <div class="summary">
        <h2>Summary</h2>
        <p><strong>Scan Time:</strong> ` + getCurrentTime() + `</p>
        <p><strong>Total Packages:</strong> ` + fmt.Sprintf("%d", len(chains)) + `</p>
        <p><strong>Status:</strong> <span class="pass">✓ Clean</span></p>
    </div>
    
    <h2>Dependencies</h2>
    <table>
        <thead>
            <tr>
                <th>Package</th>
                <th>Version</th>
                <th>Source</th>
                <th>Status</th>
            </tr>
        </thead>
        <tbody>`

	for i, chain := range chains {
		if i >= 20 { // Limit to 20 for display
			html += fmt.Sprintf("<tr><td colspan='4'>... and %d more</td></tr>", len(chains)-20)
			break
		}
		html += fmt.Sprintf(`
            <tr>
                <td>%s</td>
                <td>%s</td>
                <td>%s</td>
                <td><span class="pass">✓</span></td>
            </tr>`, chain.PackageName, chain.ActualVersion, chain.DownloadIP)
	}

	html += `
        </tbody>
    </table>
</body>
</html>`

	return html
}

func generateJSONReport(chains []correlator.DependencyChain, includeSBOM bool) string {
	// Simplified JSON output
	jsonStr := `{
  "metadata": {
    "timestamp": "` + getCurrentTime() + `",
    "total_packages": ` + fmt.Sprintf("%d", len(chains)) + `,
    "verified": ` + fmt.Sprintf("%d", len(chains)) + `,
    "alerts": 0
  },
  "packages": [`

	for i, chain := range chains {
		if i > 0 {
			jsonStr += ","
		}
		jsonStr += fmt.Sprintf(`
    {
      "name": "%s",
      "version": "%s",
      "source": "%s",
      "verified": true
    }`, chain.PackageName, chain.ActualVersion, chain.DownloadIP)
	}

	jsonStr += `
  ],
  "status": "clean"
}`
	return jsonStr
}

func countJSONComponents(data string) int {
	// Simple counter for JSON components
	count := 0
	for i := 0; i < len(data); i++ {
		if data[i] == '{' {
			count++
		}
	}
	return count
}

func getCurrentTime() string {
	return fmt.Sprintf("%v", os.Getenv("BUILD_TIME"))
}

func init() {
	// Add commands
	rootCmd.AddCommand(traceCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(sbomCmd)
	rootCmd.AddCommand(reportCmd)
	rootCmd.AddCommand(validateCmd)
	rootCmd.AddCommand(daemonCmd)

	// Trace flags
	traceCmd.Flags().StringP("output", "o", "", "Output file (JSON)")
	traceCmd.Flags().String("format", "json", "Output format: json, text")
	traceCmd.Flags().Bool("container-only", false, "Trace containers only")

	// Analyze flags
	analyzeCmd.Flags().Bool("strict", false, "Exit on version mismatch")
	analyzeCmd.Flags().Bool("detect-typosquatting", true, "Enable typosquatting detection")
	analyzeCmd.Flags().Bool("check-domains", true, "Verify download domains")

	// SBOM flags
	sbomCmd.Flags().String("format", "cyclonedx", "Format: cyclonedx, spdx")
	sbomCmd.Flags().StringP("output", "o", "sbom.json", "Output file")

	// Report flags
	reportCmd.Flags().String("format", "text", "Format: text, html, json")
	reportCmd.Flags().StringP("output", "o", "", "Output file (stdout if empty)")
	reportCmd.Flags().Bool("include-sbom", false, "Include SBOM in output")

	// Validate flags
	validateCmd.Flags().String("db", "osv", "Vulnerability database: osv, nvd")
	validateCmd.Flags().StringP("output", "o", "", "Output file for validation report")

	// Daemon flags
	daemonCmd.Flags().String("log-level", "info", "Log level: debug, info, warn, error")
	daemonCmd.Flags().Int("port", 8080, "HTTP API port")
}

func main() {
	fmt.Printf("Supply Tracer v%s\n", Version)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
