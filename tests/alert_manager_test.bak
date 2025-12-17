package tests

import (
	"fmt"
	"testing"

	"github.com/Nash0810/TraceOrigin/pkg/alert"
	"github.com/Nash0810/TraceOrigin/pkg/anomaly"
)

func TestAlertManagerCreation(t *testing.T) {
	am := alert.NewAlertManager()

	if am == nil {
		t.Error("AlertManager creation failed")
	}

	if !am.IsEnabled() {
		t.Error("AlertManager should be enabled by default")
	}

	stats := am.GetStatistics()
	if stats["total_alerts"] != 0 {
		t.Error("New AlertManager should have no alerts")
	}
}

func TestAddRemoveChannels(t *testing.T) {
	am := alert.NewAlertManager()
	emailCfg := &alert.EmailConfig{
		FromAddr: "noreply@supply-tracer.io",
		ToAddrs:  []string{"admin@example.com"},
	}
	emailCh := alert.NewEmailChannel(emailCfg)

	err := am.AddChannel(emailCh)
	if err != nil {
		t.Errorf("Failed to add channel: %v", err)
	}

	status := am.GetChannelStatus()
	if _, ok := status["email"]; !ok {
		t.Error("Email channel should be registered")
	}

	err = am.RemoveChannel("email")
	if err != nil {
		t.Errorf("Failed to remove channel: %v", err)
	}

	status = am.GetChannelStatus()
	if _, ok := status["email"]; ok {
		t.Error("Email channel should be removed")
	}
}

func TestAlertFiltering(t *testing.T) {
	am := alert.NewAlertManager()

	// Add severity filter
	sevFilter := alert.NewSeverityFilter("high")
	am.AddFilter(sevFilter)

	// Add package filter
	pkgFilter := alert.NewPackageFilter([]string{"npm"}, []string{"dev"})
	am.AddFilter(pkgFilter)

	testAlert := &alert.Alert{
		PackageName: "npm-package",
		Severity:    "critical",
	}

	// Should pass both filters
	if !am.PassFilters(testAlert) {
		t.Error("Alert should pass filters")
	}

	// Low severity should be filtered
	lowAlert := &alert.Alert{
		PackageName: "npm-package",
		Severity:    "low",
	}

	if am.PassFilters(lowAlert) {
		t.Error("Low severity alert should be filtered")
	}

	// Blocked package should be filtered
	devAlert := &alert.Alert{
		PackageName: "dev-package",
		Severity:    "high",
	}

	if am.PassFilters(devAlert) {
		t.Error("Package containing 'dev' should be filtered")
	}
}

func TestRateLimiting(t *testing.T) {
	am := alert.NewAlertManager()

	// Create multiple alerts for same package
	for i := 0; i < 11; i++ {
		allowed := am.CheckRateLimit("test-pkg")
		if i < 10 && !allowed {
			t.Errorf("First 10 alerts should be allowed, failed at #%d", i+1)
		}
		if i == 10 && allowed {
			t.Error("11th alert should exceed rate limit")
		}
	}

	// Different package should have separate limit
	allowed := am.CheckRateLimit("other-pkg")
	if !allowed {
		t.Error("Different package should have separate rate limit")
	}
}

func TestDeduplication(t *testing.T) {
	am := alert.NewAlertManager()

	anom := &anomaly.Anomaly{
		PackageName: "test-pkg",
		AnomalyType: "typosquatting",
		Severity:    "critical",
	}

	// First alert should not be duplicate
	isDup1 := am.IsDuplicate(anom)
	if isDup1 {
		t.Error("First alert should not be duplicate")
	}

	// Immediately after should be duplicate
	isDup2 := am.IsDuplicate(anom)
	if !isDup2 {
		t.Error("Immediate duplicate should be detected")
	}
}

func TestAlertHistoryStorage(t *testing.T) {
	am := alert.NewAlertManager()

	// Create mock alerts
	for i := 0; i < 5; i++ {
		testAlert := &alert.Alert{
			ID:          fmt.Sprintf("alert_%d", i),
			PackageName: fmt.Sprintf("pkg-%d", i),
			Severity:    "high",
		}
		am.StoreAlert(testAlert)
	}

	history := am.GetAlertHistory(10)
	if len(history) != 5 {
		t.Errorf("Expected 5 alerts in history, got %d", len(history))
	}

	limited := am.GetAlertHistory(2)
	if len(limited) != 2 {
		t.Errorf("Expected 2 alerts when limited, got %d", len(limited))
	}
}

func TestGetAlertsByPackage(t *testing.T) {
	am := alert.NewAlertManager()

	// Create alerts for different packages
	for i := 0; i < 3; i++ {
		alert1 := &alert.Alert{
			ID:          fmt.Sprintf("alert_%d_pkg1", i),
			PackageName: "pkg1",
			Severity:    "high",
		}
		am.StoreAlert(alert1)

		alert2 := &alert.Alert{
			ID:          fmt.Sprintf("alert_%d_pkg2", i),
			PackageName: "pkg2",
			Severity:    "medium",
		}
		am.StoreAlert(alert2)
	}

	pkg1Alerts := am.GetAlertsByPackage("pkg1")
	if len(pkg1Alerts) != 3 {
		t.Errorf("Expected 3 alerts for pkg1, got %d", len(pkg1Alerts))
	}

	pkg2Alerts := am.GetAlertsByPackage("pkg2")
	if len(pkg2Alerts) != 3 {
		t.Errorf("Expected 3 alerts for pkg2, got %d", len(pkg2Alerts))
	}
}

func TestGetAlertsBySeverity(t *testing.T) {
	am := alert.NewAlertManager()

	severities := []string{"critical", "high", "medium", "low"}
	for _, sev := range severities {
		for i := 0; i < 2; i++ {
			testAlert := &alert.Alert{
				ID:       fmt.Sprintf("alert_%s_%d", sev, i),
				Severity: sev,
			}
			am.StoreAlert(testAlert)
		}
	}

	criticalAlerts := am.GetAlertsBySeverity("critical")
	if len(criticalAlerts) != 2 {
		t.Errorf("Expected 2 critical alerts, got %d", len(criticalAlerts))
	}

	highAlerts := am.GetAlertsBySeverity("high")
	if len(highAlerts) != 2 {
		t.Errorf("Expected 2 high alerts, got %d", len(highAlerts))
	}
}

func TestAlertThresholds(t *testing.T) {
	am := alert.NewAlertManager()

	newThresholds := &alert.AlertThresholds{
		CriticalThreshold: 90.0,
		HighThreshold:     75.0,
		MediumThreshold:   50.0,
		LowThreshold:      25.0,
		MinThreatScore:    10.0,
	}

	am.SetAlertThresholds(newThresholds)

	if am.GetThresholds().CriticalThreshold != 90.0 {
		t.Error("Thresholds not updated correctly")
	}
}

func TestEnableDisable(t *testing.T) {
	am := alert.NewAlertManager()

	if !am.IsEnabled() {
		t.Error("AlertManager should be enabled by default")
	}

	am.Disable()
	if am.IsEnabled() {
		t.Error("AlertManager should be disabled")
	}

	am.Enable()
	if !am.IsEnabled() {
		t.Error("AlertManager should be enabled again")
	}
}

func TestChannelStatus(t *testing.T) {
	am := alert.NewAlertManager()

	emailCfg := &alert.EmailConfig{
		FromAddr: "noreply@example.com",
		ToAddrs:  []string{"admin@example.com"},
	}
	emailCh := alert.NewEmailChannel(emailCfg)
	am.AddChannel(emailCh)

	slackCfg := &alert.SlackConfig{
		WebhookURL: "https://hooks.slack.com/test",
		Channel:    "#alerts",
	}
	slackCh := alert.NewSlackChannel(slackCfg)
	am.AddChannel(slackCh)

	status := am.GetChannelStatus()
	if len(status) != 2 {
		t.Errorf("Expected 2 channels in status, got %d", len(status))
	}

	if !status["email"] {
		t.Error("Email channel should be healthy")
	}

	if !status["slack"] {
		t.Error("Slack channel should be healthy")
	}
}

func TestStatistics(t *testing.T) {
	am := alert.NewAlertManager()

	// Add test alerts
	for i := 0; i < 2; i++ {
		alert1 := &alert.Alert{Severity: "critical", Status: "sent"}
		alert2 := &alert.Alert{Severity: "high", Status: "failed"}
		alert3 := &alert.Alert{Severity: "medium", Status: "sent"}

		am.StoreAlert(alert1)
		am.StoreAlert(alert2)
		am.StoreAlert(alert3)
	}

	stats := am.GetStatistics()

	if stats["total_alerts"] != 6 {
		t.Errorf("Expected 6 total alerts, got %d", stats["total_alerts"])
	}

	if stats["critical"] != 2 {
		t.Errorf("Expected 2 critical alerts, got %d", stats["critical"])
	}

	if stats["sent"].(int) != 4 {
		t.Errorf("Expected 4 sent alerts, got %d", stats["sent"])
	}

	if stats["failed"].(int) != 2 {
		t.Errorf("Expected 2 failed alerts, got %d", stats["failed"])
	}
}

func TestSeverityFilter(t *testing.T) {
	filter := alert.NewSeverityFilter("high")

	testCases := []struct {
		severity string
		expected bool
	}{
		{"critical", true},
		{"high", true},
		{"medium", false},
		{"low", false},
	}

	for _, tc := range testCases {
		testAlert := &alert.Alert{Severity: tc.severity}
		result := filter.Filter(testAlert)
		if result != tc.expected {
			t.Errorf("SeverityFilter(%s) = %v, want %v", tc.severity, result, tc.expected)
		}
	}
}

func TestPackageFilter(t *testing.T) {
	allowed := []string{"npm", "pip"}
	blocked := []string{"internal", "test"}

	filter := alert.NewPackageFilter(allowed, blocked)

	testCases := []struct {
		packageName string
		expected    bool
	}{
		{"npm-lodash", true},
		{"pip-flask", true},
		{"npm-internal", false},     // contains blocked pattern
		{"ruby-gem", false},          // not in allowed list
		{"test-pkg", false},          // contains blocked pattern
	}

	for _, tc := range testCases {
		testAlert := &alert.Alert{PackageName: tc.packageName}
		result := filter.Filter(testAlert)
		if result != tc.expected {
			t.Errorf("PackageFilter(%s) = %v, want %v", tc.packageName, result, tc.expected)
		}
	}
}

func TestEmailChannel(t *testing.T) {
	config := &alert.EmailConfig{
		FromAddr: "alerts@example.com",
		ToAddrs:  []string{"admin@example.com"},
	}

	emailCh := alert.NewEmailChannel(config)

	if emailCh.Name() != "email" {
		t.Errorf("Channel name should be 'email', got %s", emailCh.Name())
	}

	if !emailCh.IsHealthy() {
		t.Error("Email channel should be healthy")
	}

	cfg := emailCh.GetConfig()
	if cfg["type"] != "email" {
		t.Error("Config type should be 'email'")
	}
}

func TestSlackChannel(t *testing.T) {
	config := &alert.SlackConfig{
		WebhookURL: "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX",
		Channel:    "#security",
		BotName:    "SecurityBot",
	}

	slackCh := alert.NewSlackChannel(config)

	if slackCh.Name() != "slack" {
		t.Errorf("Channel name should be 'slack', got %s", slackCh.Name())
	}

	if !slackCh.IsHealthy() {
		t.Error("Slack channel should be healthy")
	}

	cfg := slackCh.GetConfig()
	if cfg["type"] != "slack" {
		t.Error("Config type should be 'slack'")
	}
}

func TestWebhookChannel(t *testing.T) {
	config := &alert.WebhookConfig{
		URL:    "https://api.example.com/alerts",
		Method: "POST",
	}

	webhookCh := alert.NewWebhookChannel(config)

	if webhookCh.Name() != "webhook" {
		t.Errorf("Channel name should be 'webhook', got %s", webhookCh.Name())
	}

	if !webhookCh.IsHealthy() {
		t.Error("Webhook channel should be healthy")
	}

	cfg := webhookCh.GetConfig()
	if cfg["type"] != "webhook" {
		t.Error("Config type should be 'webhook'")
	}
}

func TestFileChannel(t *testing.T) {
	filePath := "alerts.json"
	fileCh := alert.NewFileChannel(filePath)

	if fileCh.Name() != "file" {
		t.Errorf("Channel name should be 'file', got %s", fileCh.Name())
	}

	if !fileCh.IsHealthy() {
		t.Error("File channel should be healthy")
	}
}

// Benchmarks

func BenchmarkProcessAnomaly(b *testing.B) {
	am := alert.NewAlertManager()

	emailCfg := &alert.EmailConfig{
		FromAddr: "alerts@example.com",
		ToAddrs:  []string{"admin@example.com"},
	}
	am.AddChannel(alert.NewEmailChannel(emailCfg))

	anom := &anomaly.Anomaly{
		PackageName: "test-pkg",
		AnomalyType: "typosquatting",
		Severity:    "critical",
		ThreatScore: 85.5,
		Description: "Test anomaly",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		anom.PackageName = fmt.Sprintf("pkg-%d", i)
		am.ProcessAnomaly(anom)
	}
}

func BenchmarkAlertFiltering(b *testing.B) {
	am := alert.NewAlertManager()
	am.AddFilter(alert.NewSeverityFilter("high"))
	am.AddFilter(alert.NewPackageFilter([]string{"npm"}, []string{"dev"}))

	testAlert := &alert.Alert{
		PackageName: "npm-lodash",
		Severity:    "critical",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		am.PassFilters(testAlert)
	}
}

func BenchmarkRateLimiting(b *testing.B) {
	am := alert.NewAlertManager()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		am.CheckRateLimit("test-pkg")
	}
}

func BenchmarkAlertStorage(b *testing.B) {
	am := alert.NewAlertManager()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		testAlert := &alert.Alert{
			ID:   fmt.Sprintf("alert_%d", i),
			Severity: "high",
		}
		am.StoreAlert(testAlert)
	}
}
