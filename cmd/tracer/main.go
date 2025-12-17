package main

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	"github.com/user/supply-tracer/pkg/collector"
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
	Use:   "analyze [manifest]",
	Short: "Analyze with manifest comparison",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("[*] Analyze command - coming in Iteration 2 (manifest: %s)\n", args[0])
		// TODO: Implement analysis
	},
}

var sbomCmd = &cobra.Command{
	Use:   "sbom",
	Short: "Generate SBOM from traced data",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("[*] SBOM command - coming in Iteration 2")
		// TODO: Implement SBOM generation
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
