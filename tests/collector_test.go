package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/Nash0810/TraceOrigin/pkg/collector"
)

func TestEventCollectorCreation(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	if ec == nil {
		t.Fatal("failed to create event collector")
	}
}

func TestCollectEvent(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	event := &collector.Event{
		Type:        collector.SupplyChainEventTypeProcessStart,
		Source:      collector.EventSourceEBPF,
		ProcessID:   1234,
		ProcessName: "pip",
		Severity:    collector.EventSeverityInfo,
		Data:        map[string]interface{}{"test": true},
	}

	err := ec.CollectEvent(event)
	if err != nil {
		t.Fatalf("failed to collect event: %v", err)
	}

	// Give time for async processing
	time.Sleep(100 * time.Millisecond)

	if ec.GetEventCount() != 1 {
		t.Errorf("expected 1 event, got %d", ec.GetEventCount())
	}
}

func TestCollectMultipleEvents(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	for i := 0; i < 10; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypePackageDownload,
			Source:      collector.EventSourceEBPF,
			ProcessID:   uint32(1000 + i),
			ProcessName: "npm",
			Severity:    collector.EventSeverityInfo,
		}
		_ = ec.CollectEvent(event)
	}

	time.Sleep(200 * time.Millisecond)

	if ec.GetEventCount() != 10 {
		t.Errorf("expected 10 events, got %d", ec.GetEventCount())
	}
}

func TestGetEventByID(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	event := &collector.Event{
		ID:          "test-event-1",
		Type:        collector.SupplyChainEventTypeProcessStart,
		Source:      collector.EventSourceEBPF,
		ProcessID:   1234,
		ProcessName: "python",
		Severity:    collector.EventSeverityInfo,
	}

	_ = ec.CollectEvent(event)
	time.Sleep(100 * time.Millisecond)

	retrieved, exists := ec.GetEventByID("test-event-1")
	if !exists {
		t.Error("event not found")
	}
	if retrieved.ProcessID != 1234 {
		t.Errorf("expected process ID 1234, got %d", retrieved.ProcessID)
	}
}

func TestGetEventsByContainer(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	for i := 0; i < 5; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypeProcessStart,
			Source:      collector.EventSourceEBPF,
			ContainerID: "container-1",
			ProcessID:   uint32(1000 + i),
			ProcessName: "bash",
			Severity:    collector.EventSeverityInfo,
		}
		_ = ec.CollectEvent(event)
	}

	for i := 0; i < 3; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypeProcessStart,
			Source:      collector.EventSourceEBPF,
			ContainerID: "container-2",
			ProcessID:   uint32(2000 + i),
			ProcessName: "bash",
			Severity:    collector.EventSeverityInfo,
		}
		_ = ec.CollectEvent(event)
	}

	time.Sleep(200 * time.Millisecond)

	events := ec.GetEventsByContainer("container-1")
	if len(events) != 5 {
		t.Errorf("expected 5 events for container-1, got %d", len(events))
	}

	events = ec.GetEventsByContainer("container-2")
	if len(events) != 3 {
		t.Errorf("expected 3 events for container-2, got %d", len(events))
	}
}

func TestGetEventsByType(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	for i := 0; i < 5; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypePackageDownload,
			Source:      collector.EventSourceEBPF,
			ProcessID:   uint32(1000 + i),
			ProcessName: "pip",
			Severity:    collector.EventSeverityInfo,
		}
		_ = ec.CollectEvent(event)
	}

	for i := 0; i < 3; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypeNetworkConnect,
			Source:      collector.EventSourceEBPF,
			ProcessID:   uint32(2000 + i),
			ProcessName: "curl",
			Severity:    collector.EventSeverityInfo,
		}
		_ = ec.CollectEvent(event)
	}

	time.Sleep(200 * time.Millisecond)

	events := ec.GetEventsByType(collector.SupplyChainEventTypePackageDownload)
	if len(events) != 5 {
		t.Errorf("expected 5 package download events, got %d", len(events))
	}

	events = ec.GetEventsByType(collector.SupplyChainEventTypeNetworkConnect)
	if len(events) != 3 {
		t.Errorf("expected 3 network connect events, got %d", len(events))
	}
}

func TestGetEventsBySeverity(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	severities := []collector.EventSeverity{
		collector.EventSeverityCritical,
		collector.EventSeverityHigh,
		collector.EventSeverityMedium,
	}

	for i, sev := range severities {
		for j := 0; j < 3; j++ {
			event := &collector.Event{
				Type:        collector.SupplyChainEventTypePackageDownload,
				Source:      collector.EventSourceEBPF,
				ProcessID:   uint32(1000 + i*10 + j),
				ProcessName: "pip",
				Severity:    sev,
			}
			_ = ec.CollectEvent(event)
		}
	}

	time.Sleep(300 * time.Millisecond)

	events := ec.GetEventsBySeverity(collector.EventSeverityCritical)
	if len(events) != 3 {
		t.Errorf("expected 3 critical events, got %d", len(events))
	}
}

func TestGetRecentEvents(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	for i := 0; i < 10; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypeProcessStart,
			Source:      collector.EventSourceEBPF,
			ProcessID:   uint32(1000 + i),
			ProcessName: "bash",
			Severity:    collector.EventSeverityInfo,
		}
		_ = ec.CollectEvent(event)
	}

	time.Sleep(200 * time.Millisecond)

	recent := ec.GetRecentEvents(5)
	if len(recent) != 5 {
		t.Errorf("expected 5 recent events, got %d", len(recent))
	}
}

func TestCollectorGetStatistics(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	for i := 0; i < 5; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypePackageDownload,
			Source:      collector.EventSourceEBPF,
			ProcessID:   uint32(1000 + i),
			ProcessName: "pip",
			Severity:    collector.EventSeverityHigh,
		}
		_ = ec.CollectEvent(event)
	}

	time.Sleep(200 * time.Millisecond)

	stats := ec.GetStatistics()
	if stats.TotalEvents != 5 {
		t.Errorf("expected 5 total events, got %d", stats.TotalEvents)
	}
	if stats.ProcessedEvents != 5 {
		t.Errorf("expected 5 processed events, got %d", stats.ProcessedEvents)
	}
	if stats.EventsByType[collector.SupplyChainEventTypePackageDownload] != 5 {
		t.Errorf("expected 5 package download events in stats, got %d", stats.EventsByType[collector.SupplyChainEventTypePackageDownload])
	}
}

func TestClearEvents(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	for i := 0; i < 5; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypeProcessStart,
			Source:      collector.EventSourceEBPF,
			ProcessID:   uint32(1000 + i),
			ProcessName: "bash",
			Severity:    collector.EventSeverityInfo,
		}
		_ = ec.CollectEvent(event)
	}

	time.Sleep(200 * time.Millisecond)

	if ec.GetEventCount() != 5 {
		t.Errorf("expected 5 events before clear, got %d", ec.GetEventCount())
	}

	ec.ClearEvents()

	if ec.GetEventCount() != 0 {
		t.Errorf("expected 0 events after clear, got %d", ec.GetEventCount())
	}
}

func TestRegisterProcessor(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	processorCalled := false
	processor := func(event *collector.Event) error {
		processorCalled = true
		return nil
	}

	ec.RegisterProcessor(processor)

	event := &collector.Event{
		Type:        collector.SupplyChainEventTypeProcessStart,
		Source:      collector.EventSourceEBPF,
		ProcessID:   1234,
		ProcessName: "pip",
		Severity:    collector.EventSeverityInfo,
	}

	_ = ec.CollectEvent(event)
	time.Sleep(150 * time.Millisecond)

	if !processorCalled {
		t.Error("processor was not called")
	}
}

func TestEventWithAutoID(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	event := &collector.Event{
		Type:        collector.SupplyChainEventTypeProcessStart,
		Source:      collector.EventSourceEBPF,
		ProcessID:   1234,
		ProcessName: "pip",
		Severity:    collector.EventSeverityInfo,
	}

	_ = ec.CollectEvent(event)
	time.Sleep(100 * time.Millisecond)

	retrieved, _ := ec.GetEventByID(event.ID)
	if retrieved == nil {
		t.Error("event with auto-generated ID not found")
	}
}

func TestEventFilter(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	// Add events with different attributes
	for i := 0; i < 3; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypePackageDownload,
			Source:      collector.EventSourceEBPF,
			ProcessID:   uint32(1000 + i),
			ProcessName: "pip",
			ContainerID: "container-1",
			Severity:    collector.EventSeverityHigh,
			Tags:        []string{"python", "security"},
		}
		_ = ec.CollectEvent(event)
	}

	time.Sleep(200 * time.Millisecond)

	// Filter by multiple criteria
	filter := &collector.EventFilter{
		EventTypes:  []collector.EventType{collector.SupplyChainEventTypePackageDownload},
		Sources:     []collector.EventSource{collector.EventSourceEBPF},
		Severities:  []collector.EventSeverity{collector.EventSeverityHigh},
		ContainerID: "container-1",
	}

	events := ec.GetEvents(filter)
	if len(events) != 3 {
		t.Errorf("expected 3 filtered events, got %d", len(events))
	}
}

func TestCorrelateEvents(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	event1 := &collector.Event{
		ID:          "event-1",
		Type:        collector.SupplyChainEventTypeProcessStart,
		Source:      collector.EventSourceEBPF,
		ProcessID:   1000,
		ProcessName: "bash",
		Severity:    collector.EventSeverityInfo,
	}

	event2 := &collector.Event{
		ID:          "event-2",
		Type:        collector.SupplyChainEventTypePackageDownload,
		Source:      collector.EventSourceEBPF,
		ProcessID:   1000,
		ProcessName: "pip",
		Severity:    collector.EventSeverityInfo,
	}

	_ = ec.CollectEvent(event1)
	_ = ec.CollectEvent(event2)
	time.Sleep(200 * time.Millisecond)

	err := ec.CorrelateEvents("event-2", "event-1")
	if err != nil {
		t.Errorf("failed to correlate events: %v", err)
	}

	retrieved, _ := ec.GetEventByID("event-2")
	if retrieved.ParentEventID != "event-1" {
		t.Errorf("expected parent event ID 'event-1', got '%s'", retrieved.ParentEventID)
	}
}

func TestEventChain(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	event1 := &collector.Event{
		ID:          "event-1",
		Type:        collector.SupplyChainEventTypeProcessStart,
		Source:      collector.EventSourceEBPF,
		ProcessID:   1000,
		Severity:    collector.EventSeverityInfo,
	}

	event2 := &collector.Event{
		ID:          "event-2",
		Type:        collector.SupplyChainEventTypePackageDownload,
		Source:      collector.EventSourceEBPF,
		ProcessID:   1000,
		Severity:    collector.EventSeverityInfo,
	}

	_ = ec.CollectEvent(event1)
	_ = ec.CollectEvent(event2)
	time.Sleep(200 * time.Millisecond)

	_ = ec.CorrelateEvents("event-2", "event-1")

	chain := ec.GetEventChain("event-2")
	if len(chain) < 1 {
		t.Error("expected event chain to not be empty")
	}
}

func TestExportEvents(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	event := &collector.Event{
		Type:        collector.SupplyChainEventTypeProcessStart,
		Source:      collector.EventSourceEBPF,
		ProcessID:   1234,
		ProcessName: "pip",
		Severity:    collector.EventSeverityInfo,
		Data:        map[string]interface{}{"version": "1.0"},
	}

	_ = ec.CollectEvent(event)
	time.Sleep(100 * time.Millisecond)

	exported := ec.ExportEvents(nil)
	if len(exported) != 1 {
		t.Errorf("expected 1 exported event, got %d", len(exported))
	}

	if exported[0]["process_name"] != "pip" {
		t.Errorf("expected process_name 'pip', got '%v'", exported[0]["process_name"])
	}
}

func TestConcurrentEventCollection(t *testing.T) {
	ec := collector.NewEventCollector(10000, 1000)
	ec.Start()
	defer ec.Stop()

	done := make(chan bool)
	for i := 0; i < 10; i++ {
		go func(id int) {
			for j := 0; j < 100; j++ {
				event := &collector.Event{
					Type:        collector.SupplyChainEventTypeProcessStart,
					Source:      collector.EventSourceEBPF,
					ProcessID:   uint32(1000 + id*100 + j),
					ProcessName: fmt.Sprintf("process-%d", id),
					Severity:    collector.EventSeverityInfo,
				}
				_ = ec.CollectEvent(event)
			}
			done <- true
		}(i)
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	time.Sleep(500 * time.Millisecond)

	if ec.GetEventCount() < 900 {
		t.Errorf("expected at least 900 events, got %d", ec.GetEventCount())
	}
}

func TestEventTimeline(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	for i := 0; i < 5; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypeProcessStart,
			Source:      collector.EventSourceEBPF,
			ProcessID:   uint32(1000 + i),
			ProcessName: "bash",
			Severity:    collector.EventSeverityInfo,
		}
		_ = ec.CollectEvent(event)
	}

	time.Sleep(200 * time.Millisecond)

	timeline := ec.GetEventTimeline(10 * time.Second)
	if len(timeline) == 0 {
		t.Error("expected non-empty timeline")
	}

	for _, eventTypes := range timeline {
		if len(eventTypes) == 0 {
			t.Error("expected non-empty event type list in timeline")
		}
	}
}

func TestEventCollectorMaxSize(t *testing.T) {
	ec := collector.NewEventCollector(10, 100)
	ec.Start()
	defer ec.Stop()

	for i := 0; i < 20; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypeProcessStart,
			Source:      collector.EventSourceEBPF,
			ProcessID:   uint32(1000 + i),
			ProcessName: "bash",
			Severity:    collector.EventSeverityInfo,
		}
		_ = ec.CollectEvent(event)
	}

	time.Sleep(300 * time.Millisecond)

	if ec.GetEventCount() > 10 {
		t.Errorf("expected max 10 events, got %d", ec.GetEventCount())
	}
}

func TestNilEventHandling(t *testing.T) {
	ec := collector.NewEventCollector(1000, 100)
	ec.Start()
	defer ec.Stop()

	err := ec.CollectEvent(nil)
	if err == nil {
		t.Error("expected error when collecting nil event")
	}
}

func BenchmarkCollectEvent(b *testing.B) {
	ec := collector.NewEventCollector(100000, 10000)
	ec.Start()
	defer ec.Stop()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypePackageDownload,
			Source:      collector.EventSourceEBPF,
			ProcessID:   uint32(i % 1000),
			ProcessName: "pip",
			Severity:    collector.EventSeverityInfo,
		}
		_ = ec.CollectEvent(event)
	}
}

func BenchmarkGetEvents(b *testing.B) {
	ec := collector.NewEventCollector(100000, 10000)
	ec.Start()
	defer ec.Stop()

	// Setup
	for i := 0; i < 1000; i++ {
		event := &collector.Event{
			Type:        collector.SupplyChainEventTypePackageDownload,
			Source:      collector.EventSourceEBPF,
			ProcessID:   uint32(i),
			ProcessName: "pip",
			Severity:    collector.EventSeverityInfo,
		}
		_ = ec.CollectEvent(event)
	}

	time.Sleep(500 * time.Millisecond)

	b.ResetTimer()
	filter := &collector.EventFilter{
		EventTypes: []collector.EventType{collector.SupplyChainEventTypePackageDownload},
	}

	for i := 0; i < b.N; i++ {
		_ = ec.GetEvents(filter)
	}
}
