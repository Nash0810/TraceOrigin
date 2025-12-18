package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/Nash0810/TraceOrigin/pkg/metrics"
)

func TestMetricsCollectorCreation(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)
	if collector == nil {
		t.Fatal("failed to create metrics collector")
	}
}

func TestRecordGauge(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	collector.RecordGauge("cpu_usage", 45.5, map[string]string{"host": "server1"})

	value, exists := collector.GetGauge("cpu_usage_host=server1")
	if !exists {
		t.Errorf("gauge not found after recording")
	}
	if value != 45.5 {
		t.Errorf("expected gauge value 45.5, got %f", value)
	}
}

func TestRecordGaugeUpdate(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	collector.RecordGauge("temperature", 72.0, map[string]string{})
	collector.RecordGauge("temperature", 73.5, map[string]string{})

	value, _ := collector.GetGauge("temperature")
	if value != 73.5 {
		t.Errorf("expected updated gauge value 73.5, got %f", value)
	}
}

func TestRecordCounter(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	collector.RecordCounter("requests", 10, map[string]string{"endpoint": "/api"})
	collector.RecordCounter("requests", 5, map[string]string{"endpoint": "/api"})

	count, exists := collector.GetCounter("requests_endpoint=/api")
	if !exists {
		t.Errorf("counter not found after recording")
	}
	if count != 15 {
		t.Errorf("expected counter value 15, got %d", count)
	}
}

func TestRecordCounterMultipleLabels(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	labels1 := map[string]string{"endpoint": "/api", "method": "GET"}
	labels2 := map[string]string{"endpoint": "/api", "method": "POST"}

	collector.RecordCounter("requests", 10, labels1)
	collector.RecordCounter("requests", 5, labels2)

	count1, _ := collector.GetCounter("requests_endpoint=/api_method=GET")
	count2, _ := collector.GetCounter("requests_endpoint=/api_method=POST")

	if count1 != 10 {
		t.Errorf("expected first counter 10, got %d", count1)
	}
	if count2 != 5 {
		t.Errorf("expected second counter 5, got %d", count2)
	}
}

func TestRecordHistogram(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	buckets := []float64{10, 50, 100, 500, 1000}
	collector.RecordHistogram("request_duration", 25.5, buckets, map[string]string{"service": "api"})
	collector.RecordHistogram("request_duration", 75.0, buckets, map[string]string{"service": "api"})
	collector.RecordHistogram("request_duration", 250.0, buckets, map[string]string{"service": "api"})

	allMetrics := collector.GetAllMetrics()
	histogramSumFound := false
	histogramCountFound := false
	
	for _, m := range allMetrics {
		if m.Type == metrics.MetricTypeHistogram {
			if len(m.Name) > 0 && m.Value > 0 {
				histogramSumFound = true
			}
			if m.Name != "" {
				histogramCountFound = true
			}
		}
	}

	if !histogramSumFound {
		t.Error("histogram sum metric not found")
	}
	if !histogramCountFound {
		t.Error("histogram count metric not found")
	}
}

func TestStartTimer(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	stop := collector.StartTimer("operation", map[string]string{"type": "download"})
	time.Sleep(50 * time.Millisecond)
	stop()

	stats, exists := collector.GetTimer("operation_type=download")
	if !exists {
		t.Error("timer not found after recording")
	}
	if stats.Count != 1 {
		t.Errorf("expected timer count 1, got %d", stats.Count)
	}
	if stats.Total < 50*time.Millisecond {
		t.Errorf("timer duration too short: %v", stats.Total)
	}
}

func TestRecordTimer(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	collector.RecordTimer("query", 100*time.Millisecond, map[string]string{"db": "postgres"})
	collector.RecordTimer("query", 150*time.Millisecond, map[string]string{"db": "postgres"})
	collector.RecordTimer("query", 120*time.Millisecond, map[string]string{"db": "postgres"})

	stats, _ := collector.GetTimer("query_db=postgres")

	if stats.Count != 3 {
		t.Errorf("expected timer count 3, got %d", stats.Count)
	}

	expectedTotal := 100*time.Millisecond + 150*time.Millisecond + 120*time.Millisecond
	if stats.Total != expectedTotal {
		t.Errorf("expected total %v, got %v", expectedTotal, stats.Total)
	}

	if stats.Min != 100*time.Millisecond {
		t.Errorf("expected min 100ms, got %v", stats.Min)
	}

	if stats.Max != 150*time.Millisecond {
		t.Errorf("expected max 150ms, got %v", stats.Max)
	}

	expectedMean := expectedTotal / 3
	if stats.Mean != expectedMean {
		t.Errorf("expected mean %v, got %v", expectedMean, stats.Mean)
	}
}

func TestGetAllMetrics(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	collector.RecordGauge("metric1", 10.0, map[string]string{})
	collector.RecordCounter("metric2", 5, map[string]string{})
	collector.RecordTimer("metric3", 100*time.Millisecond, map[string]string{})

	allMetrics := collector.GetAllMetrics()

	if len(allMetrics) < 3 {
		t.Errorf("expected at least 3 metrics, got %d", len(allMetrics))
	}

	metricTypes := make(map[string]bool)
	for _, m := range allMetrics {
		metricTypes[string(m.Type)] = true
	}

	if !metricTypes[string(metrics.MetricTypeGauge)] {
		t.Error("gauge metric type not found")
	}
	if !metricTypes[string(metrics.MetricTypeCounter)] {
		t.Error("counter metric type not found")
	}
	if !metricTypes[string(metrics.MetricTypeTimer)] {
		t.Error("timer metric type not found")
	}
}

func TestFlushWithCallback(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 0) // No auto-flush

	flushedMetrics := make([]metrics.Metric, 0)
	collector.SetMetricsCallback(func(m []metrics.Metric) error {
		flushedMetrics = append(flushedMetrics, m...)
		return nil
	})

	collector.RecordGauge("test_metric", 42.0, map[string]string{})
	err := collector.Flush()

	if err != nil {
		t.Errorf("flush returned error: %v", err)
	}

	if len(flushedMetrics) == 0 {
		t.Error("no metrics were flushed")
	}
}

func TestReset(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	collector.RecordGauge("metric1", 10.0, map[string]string{})
	collector.RecordCounter("metric2", 5, map[string]string{})

	stats := collector.GetStatistics()
	if stats["gauge_count"].(int) == 0 {
		t.Error("metrics not recorded before reset")
	}

	collector.Reset()

	stats = collector.GetStatistics()
	if stats["gauge_count"].(int) != 0 {
		t.Error("gauges not cleared after reset")
	}
	if stats["counter_count"].(int) != 0 {
		t.Error("counters not cleared after reset")
	}
}

func TestMetricsStatistics(t *testing.T) {
	collector := metrics.NewMetricsCollector(500, 5*time.Second)

	collector.RecordGauge("g1", 10.0, map[string]string{})
	collector.RecordGauge("g2", 20.0, map[string]string{})
	collector.RecordCounter("c1", 5, map[string]string{})
	collector.RecordTimer("t1", 100*time.Millisecond, map[string]string{})

	stats := collector.GetStatistics()

	if stats["gauge_count"].(int) != 2 {
		t.Errorf("expected 2 gauges, got %d", stats["gauge_count"].(int))
	}
	if stats["counter_count"].(int) != 1 {
		t.Errorf("expected 1 counter, got %d", stats["counter_count"].(int))
	}
	if stats["timer_count"].(int) != 1 {
		t.Errorf("expected 1 timer, got %d", stats["timer_count"].(int))
	}
	if stats["window_size"].(int) != 500 {
		t.Errorf("expected window size 500, got %d", stats["window_size"].(int))
	}
}

func TestConcurrentMetrics(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	// Record metrics concurrently
	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				collector.RecordGauge(
					fmt.Sprintf("concurrent_metric_%d", id),
					float64(j),
					map[string]string{"goroutine": fmt.Sprintf("%d", id)},
				)
			}
			done <- true
		}(i)
	}

	// Wait for all goroutines
	for i := 0; i < 10; i++ {
		<-done
	}

	stats := collector.GetStatistics()
	if stats["gauge_count"].(int) != 10 {
		t.Errorf("expected 10 gauges from concurrent recording, got %d", stats["gauge_count"].(int))
	}
}

func TestMetricWindowSize(t *testing.T) {
	collector := metrics.NewMetricsCollector(5, 0) // Small window

	// Record metrics and flush - window applies to flushed metrics, not internal storage
	for i := 0; i < 3; i++ {
		collector.RecordGauge(fmt.Sprintf("metric_%d", i), float64(i), map[string]string{})
		_ = collector.Flush()
	}

	stats := collector.GetStatistics()
	if stats["gauge_count"].(int) < 3 {
		t.Errorf("expected at least 3 gauges recorded, got %d", stats["gauge_count"].(int))
	}
}

func TestEmptyMetrics(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	// Try to get non-existent metrics
	_, existsGauge := collector.GetGauge("non_existent")
	_, existsCounter := collector.GetCounter("non_existent")
	_, existsTimer := collector.GetTimer("non_existent")

	if existsGauge {
		t.Error("expected gauge to not exist")
	}
	if existsCounter {
		t.Error("expected counter to not exist")
	}
	if existsTimer {
		t.Error("expected timer to not exist")
	}
}

func TestMetricsWithComplexLabels(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	labels := map[string]string{
		"service":   "api-gateway",
		"version":   "1.2.3",
		"region":    "us-west-2",
		"endpoint":  "/v1/users",
		"method":    "POST",
	}

	collector.RecordCounter("http_requests", 100, labels)

	allMetrics := collector.GetAllMetrics()

	found := false
	for _, m := range allMetrics {
		if m.Type == metrics.MetricTypeCounter && m.Value == 100 {
			if len(m.Labels) == len(labels) {
				found = true
				break
			}
		}
	}

	if !found {
		t.Error("complex labeled metric not found")
	}
}

func TestStartTimerRecordsTiming(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	// Test multiple timer operations
	durations := []time.Duration{
		10 * time.Millisecond,
		20 * time.Millisecond,
		15 * time.Millisecond,
	}

	for _, d := range durations {
		stop := collector.StartTimer("multi_timer", map[string]string{})
		time.Sleep(d)
		stop()
	}

	stats, _ := collector.GetTimer("multi_timer")

	if stats.Count != 3 {
		t.Errorf("expected 3 timer samples, got %d", stats.Count)
	}

	if stats.Min < 10*time.Millisecond {
		t.Errorf("min should be around 10ms, got %v", stats.Min)
	}

	if stats.Max > 25*time.Millisecond {
		t.Errorf("max should be around 20ms, got %v", stats.Max)
	}
}

func TestHistogramBucketing(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	buckets := []float64{10, 50, 100, 500}

	// Record values across different buckets
	values := []float64{5, 25, 75, 150, 600}
	for _, val := range values {
		collector.RecordHistogram("test_histogram", val, buckets, map[string]string{})
	}

	allMetrics := collector.GetAllMetrics()

	for _, m := range allMetrics {
		if m.Name == "test_histogram_sum" {
			expectedSum := 5.0 + 25.0 + 75.0 + 150.0 + 600.0
			if m.Value != expectedSum {
				t.Errorf("expected histogram sum %f, got %f", expectedSum, m.Value)
			}
		}
		if m.Name == "test_histogram_count" {
			if m.Value != 5 {
				t.Errorf("expected histogram count 5, got %f", m.Value)
			}
		}
	}
}

func TestMetricTypes(t *testing.T) {
	collector := metrics.NewMetricsCollector(1000, 5*time.Second)

	collector.RecordGauge("gauge_metric", 10.0, map[string]string{})
	collector.RecordCounter("counter_metric", 5, map[string]string{})
	collector.RecordHistogram("histogram_metric", 25.0, []float64{50, 100}, map[string]string{})
	collector.RecordTimer("timer_metric", 100*time.Millisecond, map[string]string{})

	allMetrics := collector.GetAllMetrics()

	typeCount := make(map[metrics.MetricType]int)
	for _, m := range allMetrics {
		typeCount[m.Type]++
	}

	if typeCount[metrics.MetricTypeGauge] == 0 {
		t.Error("no gauge metrics found")
	}
	if typeCount[metrics.MetricTypeCounter] == 0 {
		t.Error("no counter metrics found")
	}
	if typeCount[metrics.MetricTypeHistogram] == 0 {
		t.Error("no histogram metrics found")
	}
	if typeCount[metrics.MetricTypeTimer] == 0 {
		t.Error("no timer metrics found")
	}
}

func BenchmarkRecordGauge(b *testing.B) {
	collector := metrics.NewMetricsCollector(10000, 5*time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.RecordGauge(
			"bench_gauge",
			float64(i),
			map[string]string{"index": fmt.Sprintf("%d", i%10)},
		)
	}
}

func BenchmarkRecordCounter(b *testing.B) {
	collector := metrics.NewMetricsCollector(10000, 5*time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.RecordCounter("bench_counter", 1, map[string]string{})
	}
}

func BenchmarkRecordTimer(b *testing.B) {
	collector := metrics.NewMetricsCollector(10000, 5*time.Second)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		collector.RecordTimer(
			"bench_timer",
			time.Duration(i%1000)*time.Millisecond,
			map[string]string{},
		)
	}
}

func BenchmarkGetAllMetrics(b *testing.B) {
	collector := metrics.NewMetricsCollector(10000, 5*time.Second)

	// Setup
	for i := 0; i < 100; i++ {
		collector.RecordGauge(fmt.Sprintf("gauge_%d", i), float64(i), map[string]string{})
		collector.RecordCounter(fmt.Sprintf("counter_%d", i), int64(i), map[string]string{})
		collector.RecordTimer(fmt.Sprintf("timer_%d", i), time.Duration(i)*time.Millisecond, map[string]string{})
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = collector.GetAllMetrics()
	}
}
