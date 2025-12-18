package metrics

import (
	"fmt"
	"sync"
	"time"
)

// MetricType represents the type of metric
type MetricType string

const (
	// Gauge metrics - instantaneous values
	MetricTypeGauge MetricType = "gauge"
	// Counter metrics - monotonically increasing values
	MetricTypeCounter MetricType = "counter"
	// Histogram metrics - distribution of values
	MetricTypeHistogram MetricType = "histogram"
	// Timer metrics - measurement of time durations
	MetricTypeTimer MetricType = "timer"
)

// MetricLabel represents a key-value label
type MetricLabel struct {
	Key   string
	Value string
}

// Metric represents a single metric data point
type Metric struct {
	Name        string
	Type        MetricType
	Value       float64
	Timestamp   time.Time
	Labels      []MetricLabel
	Description string
}

// HistogramBucket represents a histogram bucket
type HistogramBucket struct {
	UpperBound float64
	Count      int64
}

// TimerSample represents a timer measurement
type TimerSample struct {
	Duration  time.Duration
	StartTime time.Time
	EndTime   time.Time
}

// MetricsCollector collects and manages application metrics
type MetricsCollector struct {
	mu              sync.RWMutex
	gauges          map[string]*Gauge
	counters        map[string]*Counter
	histograms      map[string]*Histogram
	timers          map[string]*Timer
	metrics         []Metric
	windowSize      int    // Maximum metrics to keep
	flushInterval   time.Duration
	ticker          *time.Ticker
	stopChan        chan struct{}
	metricsCallback MetricsCallback
}

// Gauge represents a gauge metric
type Gauge struct {
	Value      float64
	Labels     map[string]string
	LastUpdate time.Time
}

// Counter represents a counter metric
type Counter struct {
	Value      int64
	Labels     map[string]string
	StartTime  time.Time
	LastUpdate time.Time
}

// Histogram represents a histogram metric
type Histogram struct {
	Buckets    []HistogramBucket
	Sum        float64
	Count      int64
	Labels     map[string]string
	LastUpdate time.Time
}

// Timer represents a timer metric
type Timer struct {
	Samples    []TimerSample
	Total      time.Duration
	Count      int64
	Min        time.Duration
	Max        time.Duration
	Mean       time.Duration
	Labels     map[string]string
	LastUpdate time.Time
}

// MetricsCallback is called when metrics are flushed
type MetricsCallback func([]Metric) error

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(windowSize int, flushInterval time.Duration) *MetricsCollector {
	return &MetricsCollector{
		gauges:        make(map[string]*Gauge),
		counters:      make(map[string]*Counter),
		histograms:    make(map[string]*Histogram),
		timers:        make(map[string]*Timer),
		metrics:       make([]Metric, 0, windowSize),
		windowSize:    windowSize,
		flushInterval: flushInterval,
		stopChan:      make(chan struct{}),
	}
}

// Start begins collecting metrics with automatic flush
func (mc *MetricsCollector) Start() {
	if mc.flushInterval > 0 {
		mc.ticker = time.NewTicker(mc.flushInterval)
		go func() {
			for {
				select {
				case <-mc.ticker.C:
					_ = mc.Flush()
				case <-mc.stopChan:
					return
				}
			}
		}()
	}
}

// Stop stops the metrics collector
func (mc *MetricsCollector) Stop() {
	close(mc.stopChan)
	if mc.ticker != nil {
		mc.ticker.Stop()
	}
}

// SetMetricsCallback sets the callback for metric flushes
func (mc *MetricsCollector) SetMetricsCallback(cb MetricsCallback) {
	mc.mu.Lock()
	defer mc.mu.Unlock()
	mc.metricsCallback = cb
}

// RecordGauge records a gauge metric
func (mc *MetricsCollector) RecordGauge(name string, value float64, labels map[string]string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := mc.labelKey(name, labels)
	gauge := &Gauge{
		Value:      value,
		Labels:     labels,
		LastUpdate: time.Now(),
	}
	mc.gauges[key] = gauge
}

// RecordCounter increments a counter metric
func (mc *MetricsCollector) RecordCounter(name string, delta int64, labels map[string]string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := mc.labelKey(name, labels)
	counter, exists := mc.counters[key]
	if !exists {
		counter = &Counter{
			Labels:    labels,
			StartTime: time.Now(),
		}
		mc.counters[key] = counter
	}

	counter.Value += delta
	counter.LastUpdate = time.Now()
}

// RecordHistogram records a value in a histogram
func (mc *MetricsCollector) RecordHistogram(name string, value float64, buckets []float64, labels map[string]string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := mc.labelKey(name, labels)
	histogram, exists := mc.histograms[key]
	if !exists {
		histogram = &Histogram{
			Labels: labels,
		}
		// Initialize buckets
		for _, boundary := range buckets {
			histogram.Buckets = append(histogram.Buckets, HistogramBucket{UpperBound: boundary})
		}
		mc.histograms[key] = histogram
	}

	// Update bucket counts
	for i, bucket := range histogram.Buckets {
		if value <= bucket.UpperBound {
			histogram.Buckets[i].Count++
		}
	}

	histogram.Sum += value
	histogram.Count++
	histogram.LastUpdate = time.Now()
}

// StartTimer starts a timer and returns a function to stop it
func (mc *MetricsCollector) StartTimer(name string, labels map[string]string) func() {
	startTime := time.Now()
	return func() {
		duration := time.Since(startTime)
		mc.RecordTimer(name, duration, labels)
	}
}

// RecordTimer records a duration in a timer metric
func (mc *MetricsCollector) RecordTimer(name string, duration time.Duration, labels map[string]string) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	key := mc.labelKey(name, labels)
	timer, exists := mc.timers[key]
	if !exists {
		timer = &Timer{
			Labels: labels,
		}
		mc.timers[key] = timer
	}

	sample := TimerSample{
		Duration:  duration,
		StartTime: time.Now().Add(-duration),
		EndTime:   time.Now(),
	}
	timer.Samples = append(timer.Samples, sample)
	timer.Total += duration
	timer.Count++

	if timer.Min == 0 || duration < timer.Min {
		timer.Min = duration
	}
	if duration > timer.Max {
		timer.Max = duration
	}
	timer.Mean = timer.Total / time.Duration(timer.Count)
	timer.LastUpdate = time.Now()
}

// GetGauge retrieves a gauge metric
func (mc *MetricsCollector) GetGauge(name string) (float64, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	gauge, exists := mc.gauges[name]
	if exists {
		return gauge.Value, true
	}
	return 0, false
}

// GetCounter retrieves a counter metric
func (mc *MetricsCollector) GetCounter(name string) (int64, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	counter, exists := mc.counters[name]
	if exists {
		return counter.Value, true
	}
	return 0, false
}

// GetTimer retrieves timer statistics
func (mc *MetricsCollector) GetTimer(name string) (*TimerStats, bool) {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	timer, exists := mc.timers[name]
	if !exists {
		return nil, false
	}

	return &TimerStats{
		Count: timer.Count,
		Total: timer.Total,
		Min:   timer.Min,
		Max:   timer.Max,
		Mean:  timer.Mean,
	}, true
}

// TimerStats represents statistics for a timer
type TimerStats struct {
	Count int64
	Total time.Duration
	Min   time.Duration
	Max   time.Duration
	Mean  time.Duration
}

// GetAllMetrics returns all current metrics as a list
func (mc *MetricsCollector) GetAllMetrics() []Metric {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	metrics := make([]Metric, 0)

	// Add gauges
	for name, gauge := range mc.gauges {
		metrics = append(metrics, Metric{
			Name:      name,
			Type:      MetricTypeGauge,
			Value:     gauge.Value,
			Timestamp: gauge.LastUpdate,
			Labels:    mc.mapToLabels(gauge.Labels),
		})
	}

	// Add counters
	for name, counter := range mc.counters {
		metrics = append(metrics, Metric{
			Name:      name,
			Type:      MetricTypeCounter,
			Value:     float64(counter.Value),
			Timestamp: counter.LastUpdate,
			Labels:    mc.mapToLabels(counter.Labels),
		})
	}

	// Add histogram summaries
	for name, histogram := range mc.histograms {
		metrics = append(metrics, Metric{
			Name:      fmt.Sprintf("%s_sum", name),
			Type:      MetricTypeHistogram,
			Value:     histogram.Sum,
			Timestamp: histogram.LastUpdate,
			Labels:    mc.mapToLabels(histogram.Labels),
		})

		metrics = append(metrics, Metric{
			Name:      fmt.Sprintf("%s_count", name),
			Type:      MetricTypeHistogram,
			Value:     float64(histogram.Count),
			Timestamp: histogram.LastUpdate,
			Labels:    mc.mapToLabels(histogram.Labels),
		})
	}

	// Add timer metrics
	for name, timer := range mc.timers {
		metrics = append(metrics, Metric{
			Name:      fmt.Sprintf("%s_count", name),
			Type:      MetricTypeTimer,
			Value:     float64(timer.Count),
			Timestamp: timer.LastUpdate,
			Labels:    mc.mapToLabels(timer.Labels),
		})

		metrics = append(metrics, Metric{
			Name:      fmt.Sprintf("%s_total_ms", name),
			Type:      MetricTypeTimer,
			Value:     timer.Total.Seconds() * 1000,
			Timestamp: timer.LastUpdate,
			Labels:    mc.mapToLabels(timer.Labels),
		})

		metrics = append(metrics, Metric{
			Name:      fmt.Sprintf("%s_mean_ms", name),
			Type:      MetricTypeTimer,
			Value:     timer.Mean.Seconds() * 1000,
			Timestamp: timer.LastUpdate,
			Labels:    mc.mapToLabels(timer.Labels),
		})
	}

	return metrics
}

// Flush flushes all metrics through the callback
func (mc *MetricsCollector) Flush() error {
	metrics := mc.GetAllMetrics()

	if len(metrics) == 0 {
		return nil
	}

	mc.mu.Lock()
	if mc.metricsCallback != nil {
		mc.mu.Unlock()
		err := mc.metricsCallback(metrics)
		mc.mu.Lock()
		if err != nil {
			mc.mu.Unlock()
			return err
		}
	}
	mc.mu.Unlock()

	// Keep metrics within window size
	mc.mu.Lock()
	defer mc.mu.Unlock()

	if len(mc.metrics) >= mc.windowSize {
		// Remove oldest metrics
		removeCount := len(mc.metrics) - mc.windowSize + 1
		mc.metrics = mc.metrics[removeCount:]
	}

	mc.metrics = append(mc.metrics, metrics...)

	return nil
}

// Reset clears all metrics
func (mc *MetricsCollector) Reset() {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	mc.gauges = make(map[string]*Gauge)
	mc.counters = make(map[string]*Counter)
	mc.histograms = make(map[string]*Histogram)
	mc.timers = make(map[string]*Timer)
	mc.metrics = make([]Metric, 0, mc.windowSize)
}

// GetStatistics returns aggregate statistics
func (mc *MetricsCollector) GetStatistics() map[string]interface{} {
	mc.mu.RLock()
	defer mc.mu.RUnlock()

	return map[string]interface{}{
		"gauge_count":     len(mc.gauges),
		"counter_count":   len(mc.counters),
		"histogram_count": len(mc.histograms),
		"timer_count":     len(mc.timers),
		"total_metrics":   len(mc.metrics),
		"window_size":     mc.windowSize,
	}
}

// labelKey generates a unique key for a metric with labels
func (mc *MetricsCollector) labelKey(name string, labels map[string]string) string {
	if len(labels) == 0 {
		return name
	}

	key := name
	for k, v := range labels {
		key += fmt.Sprintf("_%s=%s", k, v)
	}
	return key
}

// mapToLabels converts a map to MetricLabel slice
func (mc *MetricsCollector) mapToLabels(labelMap map[string]string) []MetricLabel {
	labels := make([]MetricLabel, 0, len(labelMap))
	for k, v := range labelMap {
		labels = append(labels, MetricLabel{Key: k, Value: v})
	}
	return labels
}
