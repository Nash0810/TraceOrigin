package alert

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Nash0810/TraceOrigin/pkg/anomaly"
)

// AlertManager manages alert routing and notifications
type AlertManager struct {
	channels              map[string]Channel
	alertFilters          []AlertFilter
	alertHistory          []*Alert
	deduplicationCache    map[string]*Alert
	rateLimitMap          map[string]*RateLimiter
	alertThresholds       *AlertThresholds
	mu                    sync.RWMutex
	enabled               bool
	maxHistorySize        int
}

// Alert represents a notification alert
type Alert struct {
	ID                string    `json:"id"`
	AnomalyID         string    `json:"anomaly_id"`
	PackageName       string    `json:"package_name"`
	Severity          string    `json:"severity"`
	ThreatScore       float64   `json:"threat_score"`
	AnomalyType       string    `json:"anomaly_type"`
	Description       string    `json:"description"`
	Evidence          []string  `json:"evidence"`
	Remediation       string    `json:"remediation"`
	Timestamp         time.Time `json:"timestamp"`
	NotificationSent  bool      `json:"notification_sent"`
	ChannelsNotified  []string  `json:"channels_notified"`
	RetryCount        int       `json:"retry_count"`
	LastRetryTime     time.Time `json:"last_retry_time,omitempty"`
	DeduplicationKey  string    `json:"deduplication_key,omitempty"`
	Status            string    `json:"status"` // pending, sent, failed, acknowledged
}

// Channel defines a notification channel interface
type Channel interface {
	Name() string
	Send(alert *Alert) error
	IsHealthy() bool
	GetConfig() map[string]interface{}
}

// AlertFilter filters alerts before sending
type AlertFilter interface {
	Filter(alert *Alert) bool
	Name() string
}

// RateLimiter limits alert frequency per package
type RateLimiter struct {
	LastAlertTime time.Time
	AlertCount    int
	Window        time.Duration
	MaxAlerts     int
}

// AlertThresholds defines severity thresholds
type AlertThresholds struct {
	CriticalThreshold float64 // >= this value = critical
	HighThreshold     float64 // >= this value = high
	MediumThreshold   float64 // >= this value = medium
	LowThreshold      float64 // >= this value = low
	MinThreatScore    float64 // Only alert if >= this
}

// EmailConfig for email notifications
type EmailConfig struct {
	SMTPHost   string
	SMTPPort   int
	FromAddr   string
	ToAddrs    []string
	Username   string
	Password   string
	UseTLS     bool
}

// SlackConfig for Slack notifications
type SlackConfig struct {
	WebhookURL string
	Channel    string
	BotName    string
}

// WebhookConfig for generic webhooks
type WebhookConfig struct {
	URL             string
	Method          string
	Headers         map[string]string
	IncludeEvidence bool
}

// EmailChannel sends alerts via email
type EmailChannel struct {
	config  *EmailConfig
	healthy bool
}

// SlackChannel sends alerts to Slack
type SlackChannel struct {
	config  *SlackConfig
	healthy bool
}

// WebhookChannel sends alerts to webhook URLs
type WebhookChannel struct {
	config  *WebhookConfig
	healthy bool
}

// FileChannel writes alerts to a file
type FileChannel struct {
	filePath string
	healthy  bool
}

// NewAlertManager creates a new alert manager
func NewAlertManager() *AlertManager {
	return &AlertManager{
		channels:           make(map[string]Channel),
		alertFilters:       make([]AlertFilter, 0),
		alertHistory:       make([]*Alert, 0),
		deduplicationCache: make(map[string]*Alert),
		rateLimitMap:       make(map[string]*RateLimiter),
		maxHistorySize:     10000,
		enabled:            true,
		alertThresholds: &AlertThresholds{
			CriticalThreshold: 80.0,
			HighThreshold:     60.0,
			MediumThreshold:   40.0,
			LowThreshold:      20.0,
			MinThreatScore:    20.0,
		},
	}
}

// AddChannel adds a notification channel
func (am *AlertManager) AddChannel(channel Channel) error {
	if channel == nil {
		return fmt.Errorf("channel cannot be nil")
	}

	am.mu.Lock()
	defer am.mu.Unlock()

	am.channels[channel.Name()] = channel
	return nil
}

// RemoveChannel removes a notification channel
func (am *AlertManager) RemoveChannel(name string) error {
	am.mu.Lock()
	defer am.mu.Unlock()

	if _, ok := am.channels[name]; !ok {
		return fmt.Errorf("channel %s not found", name)
	}

	delete(am.channels, name)
	return nil
}

// AddFilter adds an alert filter
func (am *AlertManager) AddFilter(filter AlertFilter) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.alertFilters = append(am.alertFilters, filter)
}

// ProcessAnomaly converts an anomaly to an alert and sends it
func (am *AlertManager) ProcessAnomaly(anomaly *anomaly.Anomaly) (*Alert, error) {
	if !am.enabled {
		return nil, fmt.Errorf("alert manager is disabled")
	}

	if anomaly == nil {
		return nil, fmt.Errorf("anomaly cannot be nil")
	}

	// Check threat score threshold
	if anomaly.ThreatScore < am.alertThresholds.MinThreatScore {
		return nil, fmt.Errorf("threat score below minimum threshold")
	}

	// Create alert from anomaly
	alert := &Alert{
		ID:              generateAlertID(),
		AnomalyID:       anomaly.PackageName + "-" + anomaly.AnomalyType,
		PackageName:     anomaly.PackageName,
		Severity:        anomaly.Severity,
		ThreatScore:     anomaly.ThreatScore,
		AnomalyType:     anomaly.AnomalyType,
		Description:     anomaly.Description,
		Evidence:        anomaly.Evidence,
		Remediation:     anomaly.Remediation,
		Timestamp:       time.Now(),
		NotificationSent: false,
		ChannelsNotified: make([]string, 0),
		Status:          "pending",
		DeduplicationKey: generateDeduplicationKey(anomaly),
	}

	// Apply filters
	if !am.applyFilters(alert) {
		return alert, fmt.Errorf("alert filtered by policy")
	}

	// Check rate limiting
	if !am.checkRateLimit(alert.PackageName) {
		return alert, fmt.Errorf("rate limit exceeded for package %s", alert.PackageName)
	}

	// Check deduplication
	if am.isDuplicate(alert) {
		return alert, fmt.Errorf("alert is duplicate of recent alert")
	}

	// Send to channels
	err := am.sendToChannels(alert)
	if err == nil {
		alert.NotificationSent = true
		alert.Status = "sent"
	} else {
		alert.Status = "failed"
	}

	// Store in history
	am.storeAlert(alert)

	return alert, err
}

// sendToChannels sends alert to all registered channels
func (am *AlertManager) sendToChannels(alert *Alert) error {
	am.mu.RLock()
	channels := make(map[string]Channel)
	for name, ch := range am.channels {
		channels[name] = ch
	}
	am.mu.RUnlock()

	if len(channels) == 0 {
		return fmt.Errorf("no channels configured")
	}

	var errors []string
	successCount := 0

	for name, channel := range channels {
		if !channel.IsHealthy() {
			errors = append(errors, fmt.Sprintf("%s: channel unhealthy", name))
			continue
		}

		err := channel.Send(alert)
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", name, err))
		} else {
			alert.ChannelsNotified = append(alert.ChannelsNotified, name)
			successCount++
		}
	}

	if successCount == 0 && len(errors) > 0 {
		return fmt.Errorf("failed to send to any channel: %s", strings.Join(errors, "; "))
	}

	return nil
}

// applyFilters applies all filters to alert
func (am *AlertManager) applyFilters(alert *Alert) bool {
	am.mu.RLock()
	filters := make([]AlertFilter, len(am.alertFilters))
	copy(filters, am.alertFilters)
	am.mu.RUnlock()

	for _, filter := range filters {
		if !filter.Filter(alert) {
			return false
		}
	}
	return true
}

// checkRateLimit checks if alert exceeds rate limit
func (am *AlertManager) checkRateLimit(packageName string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()

	limiter, exists := am.rateLimitMap[packageName]
	now := time.Now()

	if !exists {
		limiter = &RateLimiter{
			LastAlertTime: now,
			AlertCount:    1,
			Window:        5 * time.Minute,
			MaxAlerts:     10,
		}
		am.rateLimitMap[packageName] = limiter
		return true
	}

	// Reset window if expired
	if now.Sub(limiter.LastAlertTime) > limiter.Window {
		limiter.LastAlertTime = now
		limiter.AlertCount = 1
		return true
	}

	// Check if within limit
	if limiter.AlertCount < limiter.MaxAlerts {
		limiter.AlertCount++
		return true
	}

	return false
}

// isDuplicate checks for duplicate alerts
func (am *AlertManager) isDuplicate(alert *Alert) bool {
	am.mu.Lock()
	defer am.mu.Unlock()

	if prev, exists := am.deduplicationCache[alert.DeduplicationKey]; exists {
		// Consider duplicate if within 5 minutes
		if time.Since(prev.Timestamp) < 5*time.Minute {
			return true
		}
	}

	return false
}

// storeAlert stores alert in history
func (am *AlertManager) storeAlert(alert *Alert) {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.alertHistory = append(am.alertHistory, alert)
	am.deduplicationCache[alert.DeduplicationKey] = alert

	// Maintain max size
	if len(am.alertHistory) > am.maxHistorySize {
		am.alertHistory = am.alertHistory[len(am.alertHistory)-am.maxHistorySize:]
	}
}

// GetAlertHistory returns recent alerts
func (am *AlertManager) GetAlertHistory(limit int) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	if limit <= 0 || limit > len(am.alertHistory) {
		limit = len(am.alertHistory)
	}

	result := make([]*Alert, limit)
	copy(result, am.alertHistory[len(am.alertHistory)-limit:])
	return result
}

// GetAlertsByPackage returns alerts for a specific package
func (am *AlertManager) GetAlertsByPackage(packageName string) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	result := make([]*Alert, 0)
	for _, alert := range am.alertHistory {
		if alert.PackageName == packageName {
			result = append(result, alert)
		}
	}
	return result
}

// GetAlertsBySeverity returns alerts of a specific severity
func (am *AlertManager) GetAlertsBySeverity(severity string) []*Alert {
	am.mu.RLock()
	defer am.mu.RUnlock()

	result := make([]*Alert, 0)
	for _, alert := range am.alertHistory {
		if alert.Severity == severity {
			result = append(result, alert)
		}
	}
	return result
}

// GetChannelStatus returns health status of all channels
func (am *AlertManager) GetChannelStatus() map[string]bool {
	am.mu.RLock()
	defer am.mu.RUnlock()

	status := make(map[string]bool)
	for name, channel := range am.channels {
		status[name] = channel.IsHealthy()
	}
	return status
}

// SetAlertThresholds sets alert severity thresholds
func (am *AlertManager) SetAlertThresholds(thresholds *AlertThresholds) {
	am.mu.Lock()
	defer am.mu.Unlock()

	if thresholds != nil {
		am.alertThresholds = thresholds
	}
}

// Enable enables the alert manager
func (am *AlertManager) Enable() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.enabled = true
}

// Disable disables the alert manager
func (am *AlertManager) Disable() {
	am.mu.Lock()
	defer am.mu.Unlock()

	am.enabled = false
}

// IsEnabled returns if alert manager is enabled
func (am *AlertManager) IsEnabled() bool {
	am.mu.RLock()
	defer am.mu.RUnlock()

	return am.enabled
}

// GetStatistics returns alert statistics
func (am *AlertManager) GetStatistics() map[string]interface{} {
	am.mu.RLock()
	defer am.mu.RUnlock()

	critical := 0
	high := 0
	medium := 0
	low := 0
	failed := 0
	sent := 0

	for _, alert := range am.alertHistory {
		switch alert.Severity {
		case "critical":
			critical++
		case "high":
			high++
		case "medium":
			medium++
		case "low":
			low++
		}

		if alert.Status == "sent" {
			sent++
		} else if alert.Status == "failed" {
			failed++
		}
	}

	return map[string]interface{}{
		"total_alerts":    len(am.alertHistory),
		"critical":        critical,
		"high":            high,
		"medium":          medium,
		"low":             low,
		"sent":            sent,
		"failed":          failed,
		"channels_count":  len(am.channels),
		"filters_count":   len(am.alertFilters),
	}
}

// PassFilters checks if alert passes all configured filters
func (am *AlertManager) PassFilters(alert *Alert) bool {
	return am.applyFilters(alert)
}

// CheckRateLimit checks if alert is within rate limit
func (am *AlertManager) CheckRateLimit(packageName string) bool {
	return am.checkRateLimit(packageName)
}

// IsDuplicate checks if anomaly is a duplicate
func (am *AlertManager) IsDuplicate(anomaly *anomaly.Anomaly) bool {
	dedupeKey := generateDeduplicationKey(anomaly)
	am.mu.Lock()
	defer am.mu.Unlock()

	if prev, exists := am.deduplicationCache[dedupeKey]; exists {
		if time.Since(prev.Timestamp) < 5*time.Minute {
			return true
		}
	}
	am.deduplicationCache[dedupeKey] = &Alert{Timestamp: time.Now()}
	return false
}

// StoreAlert stores an alert in history
func (am *AlertManager) StoreAlert(alert *Alert) {
	am.storeAlert(alert)
}

// GetThresholds returns current alert thresholds
func (am *AlertManager) GetThresholds() *AlertThresholds {
	am.mu.RLock()
	defer am.mu.RUnlock()

	return am.alertThresholds
}

// Helper functions

func generateAlertID() string {
	return fmt.Sprintf("alert_%d", time.Now().UnixNano())
}

func generateDeduplicationKey(anomaly *anomaly.Anomaly) string {
	return fmt.Sprintf("%s_%s_%s", anomaly.PackageName, anomaly.AnomalyType, anomaly.Severity)
}

// SeverityFilter filters by severity level
type SeverityFilter struct {
	minimumSeverity string
}

// NewSeverityFilter creates a severity filter
func NewSeverityFilter(minimumSeverity string) *SeverityFilter {
	return &SeverityFilter{minimumSeverity: minimumSeverity}
}

// Filter implements AlertFilter
func (sf *SeverityFilter) Filter(alert *Alert) bool {
	severityRank := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	minRank := severityRank[sf.minimumSeverity]
	alertRank := severityRank[alert.Severity]

	return alertRank >= minRank
}

// Name implements AlertFilter
func (sf *SeverityFilter) Name() string {
	return "SeverityFilter"
}

// PackageFilter filters by package patterns
type PackageFilter struct {
	allowedPatterns []string
	blockedPatterns []string
}

// NewPackageFilter creates a package filter
func NewPackageFilter(allowed, blocked []string) *PackageFilter {
	return &PackageFilter{
		allowedPatterns: allowed,
		blockedPatterns: blocked,
	}
}

// Filter implements AlertFilter
func (pf *PackageFilter) Filter(alert *Alert) bool {
	for _, pattern := range pf.blockedPatterns {
		if strings.Contains(alert.PackageName, pattern) {
			return false
		}
	}

	if len(pf.allowedPatterns) > 0 {
		found := false
		for _, pattern := range pf.allowedPatterns {
			if strings.Contains(alert.PackageName, pattern) {
				found = true
				break
			}
		}
		return found
	}

	return true
}

// Name implements AlertFilter
func (pf *PackageFilter) Name() string {
	return "PackageFilter"
}

// NewEmailChannel creates an email notification channel
func NewEmailChannel(config *EmailConfig) *EmailChannel {
	return &EmailChannel{config: config, healthy: true}
}

// Name implements Channel
func (ec *EmailChannel) Name() string {
	return "email"
}

// Send implements Channel
func (ec *EmailChannel) Send(alert *Alert) error {
	if ec.config == nil || len(ec.config.ToAddrs) == 0 {
		return fmt.Errorf("email config invalid")
	}

	// In production, would send via SMTP
	// Simplified implementation for now
	_ = fmt.Sprintf(
		"Subject: [%s] Security Alert: %s\n\n"+
			"Package: %s\n"+
			"Severity: %s\n"+
			"Threat Score: %.1f\n"+
			"Type: %s\n\n"+
			"Description:\n%s\n\n"+
			"Evidence:\n%s\n\n"+
			"Remediation:\n%s\n",
		strings.ToUpper(alert.Severity),
		alert.PackageName,
		alert.PackageName,
		alert.Severity,
		alert.ThreatScore,
		alert.AnomalyType,
		alert.Description,
		strings.Join(alert.Evidence, "\n"),
		alert.Remediation,
	)

	return nil
}

// IsHealthy implements Channel
func (ec *EmailChannel) IsHealthy() bool {
	return ec.healthy && ec.config != nil
}

// GetConfig implements Channel
func (ec *EmailChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"type":     "email",
		"from":     ec.config.FromAddr,
		"to_count": len(ec.config.ToAddrs),
	}
}

// NewSlackChannel creates a Slack notification channel
func NewSlackChannel(config *SlackConfig) *SlackChannel {
	return &SlackChannel{config: config, healthy: true}
}

// Name implements Channel
func (sc *SlackChannel) Name() string {
	return "slack"
}

// Send implements Channel
func (sc *SlackChannel) Send(alert *Alert) error {
	if sc.config == nil || sc.config.WebhookURL == "" {
		return fmt.Errorf("slack config invalid")
	}

	color := "danger"
	if alert.Severity == "high" {
		color = "warning"
	} else if alert.Severity == "medium" {
		color = "#0099ff"
	}

	payload := map[string]interface{}{
		"channel":    sc.config.Channel,
		"username":   sc.config.BotName,
		"attachments": []map[string]interface{}{
			{
				"color": color,
				"title": fmt.Sprintf("[%s] %s", strings.ToUpper(alert.Severity), alert.PackageName),
				"text":  alert.Description,
				"fields": []map[string]interface{}{
					{
						"title": "Threat Score",
						"value": fmt.Sprintf("%.1f", alert.ThreatScore),
						"short": true,
					},
					{
						"title": "Type",
						"value": alert.AnomalyType,
						"short": true,
					},
					{
						"title": "Remediation",
						"value": alert.Remediation,
						"short": false,
					},
				},
			},
		},
	}

	jsonPayload, _ := json.Marshal(payload)
	resp, err := http.Post(sc.config.WebhookURL, "application/json", strings.NewReader(string(jsonPayload)))
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("slack webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// IsHealthy implements Channel
func (sc *SlackChannel) IsHealthy() bool {
	return sc.healthy && sc.config != nil
}

// GetConfig implements Channel
func (sc *SlackChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"type":    "slack",
		"channel": sc.config.Channel,
	}
}

// NewWebhookChannel creates a generic webhook notification channel
func NewWebhookChannel(config *WebhookConfig) *WebhookChannel {
	return &WebhookChannel{config: config, healthy: true}
}

// Name implements Channel
func (wc *WebhookChannel) Name() string {
	return "webhook"
}

// Send implements Channel
func (wc *WebhookChannel) Send(alert *Alert) error {
	if wc.config == nil || wc.config.URL == "" {
		return fmt.Errorf("webhook config invalid")
	}

	method := wc.config.Method
	if method == "" {
		method = "POST"
	}

	alertJSON, err := json.Marshal(alert)
	if err != nil {
		return err
	}

	req, err := http.NewRequest(method, wc.config.URL, strings.NewReader(string(alertJSON)))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", "application/json")
	for key, value := range wc.config.Headers {
		req.Header.Set(key, value)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("webhook returned status %d", resp.StatusCode)
	}

	return nil
}

// IsHealthy implements Channel
func (wc *WebhookChannel) IsHealthy() bool {
	return wc.healthy && wc.config != nil
}

// GetConfig implements Channel
func (wc *WebhookChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"type": "webhook",
		"url":  wc.config.URL,
	}
}

// NewFileChannel creates a file-based notification channel
func NewFileChannel(filePath string) *FileChannel {
	return &FileChannel{filePath: filePath, healthy: true}
}

// Name implements Channel
func (fc *FileChannel) Name() string {
	return "file"
}

// Send implements Channel
func (fc *FileChannel) Send(alert *Alert) error {
	if fc.filePath == "" {
		return fmt.Errorf("file path not configured")
	}

	// In a real implementation, would append to file
	// For now, just verify configuration
	return nil
}

// IsHealthy implements Channel
func (fc *FileChannel) IsHealthy() bool {
	return fc.healthy
}

// GetConfig implements Channel
func (fc *FileChannel) GetConfig() map[string]interface{} {
	return map[string]interface{}{
		"type":      "file",
		"file_path": fc.filePath,
	}
}
