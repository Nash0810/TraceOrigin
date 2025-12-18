package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/Nash0810/TraceOrigin/pkg/export"
)

func TestExporterCreation(t *testing.T) {
	config := export.ExportConfig{
		Format:    export.FormatJSON,
		Target:    export.TargetFile,
		Filename:  "test.json",
		BatchSize: 100,
	}

	exporter := export.NewExporter(config)
	if exporter == nil {
		t.Fatal("failed to create exporter")
	}
}

func TestAddEntry(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	entry := export.ExportEntry{
		Type:           "vulnerability",
		PackageName:    "requests",
		PackageVersion: "2.25.0",
		PackageManager: "pip",
		Severity:       "high",
		Description:    "Test vulnerability",
		SourceURL:      "https://example.com",
		Status:         "active",
	}

	exporter.AddEntry(entry)

	if exporter.GetEntryCount() != 1 {
		t.Errorf("expected 1 entry, got %d", exporter.GetEntryCount())
	}
}

func TestAddMultipleEntries(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	entries := []export.ExportEntry{
		{Type: "vulnerability", PackageName: "pkg1", Severity: "high"},
		{Type: "vulnerability", PackageName: "pkg2", Severity: "medium"},
		{Type: "vulnerability", PackageName: "pkg3", Severity: "low"},
	}

	exporter.AddEntries(entries)

	if exporter.GetEntryCount() != 3 {
		t.Errorf("expected 3 entries, got %d", exporter.GetEntryCount())
	}
}

func TestExportJSON(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
		Pretty:   true,
	}

	exporter := export.NewExporter(config)
	exporter.AddEntry(export.ExportEntry{
		Type:        "vulnerability",
		PackageName: "test-pkg",
		Severity:    "critical",
	})

	result, err := exporter.Export()
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if !result.Success {
		t.Fatal("export should be successful")
	}

	if result.RecordsExported != 1 {
		t.Errorf("expected 1 record exported, got %d", result.RecordsExported)
	}
}

func TestExportCSV(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatCSV,
		Target:   export.TargetFile,
		Filename: "test.csv",
	}

	exporter := export.NewExporter(config)
	exporter.AddEntry(export.ExportEntry{
		Type:           "vulnerability",
		PackageName:    "requests",
		PackageVersion: "2.25.0",
		Severity:       "high",
	})

	result, err := exporter.Export()
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if !result.Success {
		t.Fatal("export should be successful")
	}
}

func TestExportXML(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatXML,
		Target:   export.TargetFile,
		Filename: "test.xml",
	}

	exporter := export.NewExporter(config)
	exporter.AddEntry(export.ExportEntry{
		Type:        "vulnerability",
		PackageName: "pkg1",
		Severity:    "high",
	})

	result, err := exporter.Export()
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if !result.Success {
		t.Fatal("export should be successful")
	}
}

func TestExportYAML(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatYAML,
		Target:   export.TargetFile,
		Filename: "test.yaml",
	}

	exporter := export.NewExporter(config)
	exporter.AddEntry(export.ExportEntry{
		Type:        "vulnerability",
		PackageName: "pkg1",
		Severity:    "medium",
	})

	result, err := exporter.Export()
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if !result.Success {
		t.Fatal("export should be successful")
	}
}

func TestExportMarkdown(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatMarkdown,
		Target:   export.TargetFile,
		Filename: "test.md",
	}

	exporter := export.NewExporter(config)

	entries := []export.ExportEntry{
		{Type: "vulnerability", PackageName: "pkg1", Severity: "critical"},
		{Type: "vulnerability", PackageName: "pkg2", Severity: "high"},
		{Type: "vulnerability", PackageName: "pkg3", Severity: "medium"},
	}

	exporter.AddEntries(entries)

	result, err := exporter.Export()
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if !result.Success {
		t.Fatal("export should be successful")
	}

	if result.RecordsExported != 3 {
		t.Errorf("expected 3 records, got %d", result.RecordsExported)
	}
}

func TestFilterBySeverity(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	entries := []export.ExportEntry{
		{Type: "vulnerability", PackageName: "pkg1", Severity: "critical"},
		{Type: "vulnerability", PackageName: "pkg2", Severity: "high"},
		{Type: "vulnerability", PackageName: "pkg3", Severity: "low"},
	}

	exporter.AddEntries(entries)

	exporter.FilterBySeverity("high")
	exporter.ApplyFilters()

	if exporter.GetEntryCount() != 1 {
		t.Errorf("expected 1 entry after filter, got %d", exporter.GetEntryCount())
	}
}

func TestFilterByPackage(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	entries := []export.ExportEntry{
		{Type: "vulnerability", PackageName: "flask-app"},
		{Type: "vulnerability", PackageName: "django-rest"},
		{Type: "vulnerability", PackageName: "flask-cors"},
	}

	exporter.AddEntries(entries)

	err := exporter.FilterByPackage("flask.*")
	if err != nil {
		t.Fatalf("failed to set package filter: %v", err)
	}

	exporter.ApplyFilters()

	if exporter.GetEntryCount() != 2 {
		t.Errorf("expected 2 entries matching flask pattern, got %d", exporter.GetEntryCount())
	}
}

func TestFilterByDateRange(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	now := time.Now()
	yesterday := now.AddDate(0, 0, -1)
	twoDaysAgo := now.AddDate(0, 0, -2)

	entries := []export.ExportEntry{
		{Type: "vulnerability", PackageName: "pkg1", DetectedAt: now},
		{Type: "vulnerability", PackageName: "pkg2", DetectedAt: yesterday},
		{Type: "vulnerability", PackageName: "pkg3", DetectedAt: twoDaysAgo},
	}

	exporter.AddEntries(entries)

	// Filter for last 2 days
	exporter.FilterByDateRange(yesterday.AddDate(0, 0, -1), now.AddDate(0, 0, 1))
	exporter.ApplyFilters()

	if exporter.GetEntryCount() != 2 {
		t.Errorf("expected 2 entries in date range, got %d", exporter.GetEntryCount())
	}
}

func TestSortByDate(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	now := time.Now()
	yesterday := now.AddDate(0, 0, -1)
	tomorrow := now.AddDate(0, 0, 1)

	entries := []export.ExportEntry{
		{Type: "vulnerability", PackageName: "pkg1", DetectedAt: tomorrow},
		{Type: "vulnerability", PackageName: "pkg2", DetectedAt: now},
		{Type: "vulnerability", PackageName: "pkg3", DetectedAt: yesterday},
	}

	exporter.AddEntries(entries)
	exporter.SortByDate(true)

	sorted := exporter.GetEntries()
	if sorted[0].DetectedAt.After(sorted[1].DetectedAt) {
		t.Error("entries should be sorted in ascending order by date")
	}
}

func TestSortBySeverity(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	entries := []export.ExportEntry{
		{Type: "vulnerability", PackageName: "pkg1", Severity: "low"},
		{Type: "vulnerability", PackageName: "pkg2", Severity: "critical"},
		{Type: "vulnerability", PackageName: "pkg3", Severity: "medium"},
	}

	exporter.AddEntries(entries)
	exporter.SortBySeverity()

	sorted := exporter.GetEntries()
	if sorted[0].Severity != "critical" {
		t.Error("critical severity should be first")
	}
	if sorted[len(sorted)-1].Severity != "low" {
		t.Error("low severity should be last")
	}
}

func TestExportGetStatistics(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	entries := []export.ExportEntry{
		{Type: "vulnerability", PackageName: "pkg1", Severity: "critical", PackageManager: "pip"},
		{Type: "vulnerability", PackageName: "pkg2", Severity: "high", PackageManager: "npm"},
		{Type: "vulnerability", PackageName: "pkg3", Severity: "critical", PackageManager: "pip"},
	}

	exporter.AddEntries(entries)

	stats := exporter.GetStatistics()

	if stats["total_entries"] != 3 {
		t.Errorf("expected 3 total entries, got %v", stats["total_entries"])
	}

	severityStats := stats["by_severity"].(map[string]int)
	if severityStats["critical"] != 2 {
		t.Errorf("expected 2 critical entries, got %d", severityStats["critical"])
	}
}

func TestGetEntries(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	entries := []export.ExportEntry{
		{Type: "vulnerability", PackageName: "pkg1"},
		{Type: "vulnerability", PackageName: "pkg2"},
	}

	exporter.AddEntries(entries)

	retrieved := exporter.GetEntries()
	if len(retrieved) != 2 {
		t.Errorf("expected 2 entries, got %d", len(retrieved))
	}
}

func TestClearEntries(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	exporter.AddEntry(export.ExportEntry{
		Type:        "vulnerability",
		PackageName: "pkg1",
	})

	exporter.ClearEntries()

	if exporter.GetEntryCount() != 0 {
		t.Errorf("expected 0 entries after clear, got %d", exporter.GetEntryCount())
	}
}

func TestValidateExportConfig(t *testing.T) {
	invalidConfig := export.ExportConfig{
		Format:    "",
		Target:    "",
		BatchSize: 0,
	}

	errors := export.ValidateExportConfig(invalidConfig)
	if len(errors) == 0 {
		t.Fatal("expected validation errors for invalid config")
	}
}

func TestValidateExportConfigValid(t *testing.T) {
	validConfig := export.ExportConfig{
		Format:    export.FormatJSON,
		Target:    export.TargetFile,
		BatchSize: 100,
		ChunkSize: 1024,
	}

	errors := export.ValidateExportConfig(validConfig)
	if len(errors) > 0 {
		t.Errorf("expected no validation errors, got %v", errors)
	}
}

func TestBatchExport(t *testing.T) {
	config := export.ExportConfig{
		Format:    export.FormatJSON,
		Target:    export.TargetFile,
		Filename:  "test.json",
		BatchSize: 2,
	}

	exporter := export.NewExporter(config)

	for i := 0; i < 5; i++ {
		exporter.AddEntry(export.ExportEntry{
			Type:        "vulnerability",
			PackageName: fmt.Sprintf("pkg%d", i),
		})
	}

	batchCount := 0
	exporter.BatchExport(func(batch []export.ExportEntry) error {
		batchCount++
		if len(batch) == 0 {
			return fmt.Errorf("empty batch")
		}
		return nil
	})

	if batchCount != 3 {
		t.Errorf("expected 3 batches, got %d", batchCount)
	}
}

func TestExportWithMetadata(t *testing.T) {
	config := export.ExportConfig{
		Format:         export.FormatJSON,
		Target:         export.TargetFile,
		Filename:       "test.json",
		IncludeMetadata: true,
	}

	exporter := export.NewExporter(config)
	exporter.AddEntry(export.ExportEntry{
		Type:        "vulnerability",
		PackageName: "pkg1",
		Metadata: map[string]interface{}{
			"source":    "cve",
			"confirmed": true,
		},
	})

	result, err := exporter.Export()
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if !result.Success {
		t.Fatal("export should succeed")
	}
}

func TestConcurrentAddEntry(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(index int) {
			exporter.AddEntry(export.ExportEntry{
				Type:        "vulnerability",
				PackageName: fmt.Sprintf("pkg%d", index),
			})
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	if exporter.GetEntryCount() != 10 {
		t.Errorf("expected 10 entries, got %d", exporter.GetEntryCount())
	}
}

func TestExportResultMetadata(t *testing.T) {
	config := export.ExportConfig{
		Format:      export.FormatJSON,
		Target:      export.TargetFile,
		Filename:    "test.json",
		Compression: true,
		Encryption:  true,
	}

	exporter := export.NewExporter(config)
	exporter.AddEntry(export.ExportEntry{
		Type:        "vulnerability",
		PackageName: "pkg1",
	})

	result, err := exporter.Export()
	if err != nil {
		t.Fatalf("export failed: %v", err)
	}

	if result.Metadata["format"] != "json" {
		t.Error("format should be in metadata")
	}

	if result.Metadata["compression"] != true {
		t.Error("compression flag should be in metadata")
	}
}

func TestExportFormatWithTags(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	entry := export.ExportEntry{
		Type:        "vulnerability",
		PackageName: "pkg1",
		Tags:        []string{"critical", "supply-chain", "tested"},
	}

	exporter.AddEntry(entry)

	retrieved := exporter.GetEntries()
	if len(retrieved[0].Tags) != 3 {
		t.Errorf("expected 3 tags, got %d", len(retrieved[0].Tags))
	}
}

func TestFilterInvalidRegex(t *testing.T) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	err := exporter.FilterByPackage("[invalid(regex")
	if err == nil {
		t.Fatal("expected error for invalid regex")
	}
}

// Benchmarks

func BenchmarkAddEntry(b *testing.B) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	entry := export.ExportEntry{
		Type:        "vulnerability",
		PackageName: "test",
		Severity:    "high",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exporter.AddEntry(entry)
	}
}

func BenchmarkExportJSON(b *testing.B) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
		Pretty:   true,
	}

	exporter := export.NewExporter(config)

	for i := 0; i < 100; i++ {
		exporter.AddEntry(export.ExportEntry{
			Type:        "vulnerability",
			PackageName: fmt.Sprintf("pkg%d", i),
			Severity:    "high",
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exporter.Export()
	}
}

func BenchmarkSortByDate(b *testing.B) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	now := time.Now()
	for i := 0; i < 100; i++ {
		exporter.AddEntry(export.ExportEntry{
			Type:        "vulnerability",
			PackageName: fmt.Sprintf("pkg%d", i),
			DetectedAt:  now.AddDate(0, 0, -i),
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exporter.SortByDate(true)
	}
}

func BenchmarkExporterGetStatistics(b *testing.B) {
	config := export.ExportConfig{
		Format:   export.FormatJSON,
		Target:   export.TargetFile,
		Filename: "test.json",
	}

	exporter := export.NewExporter(config)

	for i := 0; i < 100; i++ {
		exporter.AddEntry(export.ExportEntry{
			Type:           "vulnerability",
			PackageName:    fmt.Sprintf("pkg%d", i),
			Severity:       []string{"critical", "high", "medium"}[i%3],
			PackageManager: []string{"pip", "npm"}[i%2],
		})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		exporter.GetStatistics()
	}
}
