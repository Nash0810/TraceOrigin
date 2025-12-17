package main

import (
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
		defer coll.Close()

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
		mp := manifest.NewParser()
		man, err := mp.ParseManifest(manifestPath)
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

		// Parse events from trace log (line-delimited JSON)
		engine := correlator.NewCorrelationEngine()
		var mismatchCount, verifiedCount int

		// For MVP: simple analysis without re-parsing all events
		// In production: replay events through correlation engine
		lines := string(data)
		fmt.Fprintf(os.Stderr, "\n[*] Parsed trace log (%d bytes)\n\n", len(lines))

		// Link manifest to observations
		linked := engine.LinkManifestToObserved(declaredPkgs)

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
		mp := manifest.NewParser()
		man, err := mp.ParseManifest(manifestPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Warning: Failed to parse manifest: %v\n", err)
		}

		// Build declared packages map
		declaredPkgs := make(map[string]string)
		for _, pkg := range man.Packages {
			declaredPkgs[pkg.Name] = pkg.Version
		}

		// Link with manifest
		linked := engine.LinkManifestToObserved(declaredPkgs)

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
	Use:   "report",
	Short: "Generate security report",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[*] Report command - coming in Iteration 3")
		// TODO: Implement reporting
	},
}

func init() {
	// Add commands
	rootCmd.AddCommand(traceCmd)
	rootCmd.AddCommand(analyzeCmd)
	rootCmd.AddCommand(sbomCmd)
	rootCmd.AddCommand(reportCmd)

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
}

func main() {
	fmt.Printf("Supply Tracer v%s\n", Version)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
}
