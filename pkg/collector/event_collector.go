package collector

import (
	"fmt"
	"sync"
	"time"
)

// SupplyChainEventType represents the type of supply chain event
type SupplyChainEventType string

const (
	// Process events
	SupplyChainEventTypeProcessStart    SupplyChainEventType = "process_start"
	SupplyChainEventTypeProcessEnd      SupplyChainEventType = "process_end"
	SupplyChainEventTypeProcessExecve   SupplyChainEventType = "process_execve"
	SupplyChainEventTypeProcessSignal   SupplyChainEventType = "process_signal"
	
	// Network events
	SupplyChainEventTypeNetworkConnect  SupplyChainEventType = "network_connect"
	SupplyChainEventTypeNetworkClose    SupplyChainEventType = "network_close"
	SupplyChainEventTypeNetworkSend     SupplyChainEventType = "network_send"
	SupplyChainEventTypeNetworkReceive  SupplyChainEventType = "network_receive"
	
	// File events
	SupplyChainEventTypeFileOpen        SupplyChainEventType = "file_open"
	SupplyChainEventTypeFileClose       SupplyChainEventType = "file_close"
	SupplyChainEventTypeFileWrite       SupplyChainEventType = "file_write"
	SupplyChainEventTypeFileDelete      SupplyChainEventType = "file_delete"
	
	// Package manager events
	SupplyChainEventTypePackageDownload SupplyChainEventType = "package_download"
	SupplyChainEventTypePackageInstall  SupplyChainEventType = "package_install"
	SupplyChainEventTypePackageVerify   SupplyChainEventType = "package_verify"
	
	// Anomaly events
	SupplyChainEventTypeAnomaly         SupplyChainEventType = "anomaly"
)

// EventType represents the type of supply chain event (alias for compatibility)
type EventType = SupplyChainEventType

// EventSource indicates where an event originated
type EventSource string

const (
	EventSourceEBPF      EventSource = "ebpf"
	EventSourceContainer EventSource = "container"
	EventSourceHost      EventSource = "host"
	EventSourceManifest  EventSource = "manifest"
)

// Event represents a supply chain event
type Event struct {
	ID              string                 `json:"id"`
	Type            EventType              `json:"type"`
	Source          EventSource            `json:"source"`
	Timestamp       time.Time              `json:"timestamp"`
	ProcessID       uint32                 `json:"process_id"`
	ContainerID     string                 `json:"container_id"`
	ProcessName     string                 `json:"process_name"`
	User            string                 `json:"user"`
	Hostname        string                 `json:"hostname"`
	Data            map[string]interface{} `json:"data"`
	Severity        EventSeverity          `json:"severity"`
	Tags            []string               `json:"tags"`
	CorrelationID   string                 `json:"correlation_id"`
	ParentEventID   string                 `json:"parent_event_id"`
}

// EventSeverity indicates the severity level of an event
type EventSeverity string

const (
	EventSeverityCritical EventSeverity = "critical"
	EventSeverityHigh     EventSeverity = "high"
	EventSeverityMedium   EventSeverity = "medium"
	EventSeverityLow      EventSeverity = "low"
	EventSeverityInfo     EventSeverity = "info"
)

// EventFilter defines criteria for filtering events
type EventFilter struct {
	EventTypes    []EventType
	Sources       []EventSource
	Severities    []EventSeverity
	ContainerID   string
	ProcessName   string
	TimeRange     *TimeRange
	Tags          []string
}

// TimeRange defines a time window for filtering
type TimeRange struct {
	Start time.Time
	End   time.Time
}

// EventProcessor is a function that processes events
type EventProcessor func(*Event) error

// EventCollector collects and manages supply chain events
type EventCollector struct {
	mu                sync.RWMutex
	events            []*Event
	maxEvents         int
	eventChan         chan *Event
	processorsLock    sync.RWMutex
	processors        []EventProcessor
	stats             *CollectorStats
	ticker            *time.Ticker
	stopChan          chan struct{}
	retentionDuration time.Duration
}

// CollectorStats tracks event collection statistics
type CollectorStats struct {
	TotalEvents      int64
	ProcessedEvents  int64
	DroppedEvents    int64
	FailedEvents     int64
	EventsByType     map[EventType]int64
	EventsBySeverity map[EventSeverity]int64
	LastEvent        time.Time
}

// NewEventCollector creates a new event collector
func NewEventCollector(maxEvents int, eventChanSize int) *EventCollector {
	return &EventCollector{
		events:        make([]*Event, 0, maxEvents),
		maxEvents:     maxEvents,
		eventChan:     make(chan *Event, eventChanSize),
		processors:    make([]EventProcessor, 0),
		stats:         &CollectorStats{
			EventsByType:     make(map[EventType]int64),
			EventsBySeverity: make(map[EventSeverity]int64),
		},
		stopChan:          make(chan struct{}),
		retentionDuration: 24 * time.Hour,
	}
}

// Start starts the event collector background processing
func (ec *EventCollector) Start() {
	go ec.processEventQueue()
	go ec.cleanupExpiredEvents()
}

// Stop stops the event collector
func (ec *EventCollector) Stop() {
	close(ec.stopChan)
	if ec.ticker != nil {
		ec.ticker.Stop()
	}
}

// CollectEvent adds an event to the collector
func (ec *EventCollector) CollectEvent(event *Event) error {
	if event == nil {
		return fmt.Errorf("event cannot be nil")
	}

	if event.ID == "" {
		event.ID = generateEventID()
	}

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now()
	}

	select {
	case ec.eventChan <- event:
		return nil
	case <-ec.stopChan:
		return fmt.Errorf("collector stopped")
	default:
		ec.mu.Lock()
		ec.stats.DroppedEvents++
		ec.mu.Unlock()
		return fmt.Errorf("event queue full")
	}
}

// RegisterProcessor registers an event processor
func (ec *EventCollector) RegisterProcessor(processor EventProcessor) {
	ec.processorsLock.Lock()
	defer ec.processorsLock.Unlock()
	ec.processors = append(ec.processors, processor)
}

// GetEvents retrieves events matching the filter
func (ec *EventCollector) GetEvents(filter *EventFilter) []*Event {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	result := make([]*Event, 0)

	for _, event := range ec.events {
		if ec.matchesFilter(event, filter) {
			result = append(result, event)
		}
	}

	return result
}

// GetEventByID retrieves a specific event by ID
func (ec *EventCollector) GetEventByID(id string) (*Event, bool) {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	for _, event := range ec.events {
		if event.ID == id {
			return event, true
		}
	}
	return nil, false
}

// GetEventsByContainer retrieves events for a specific container
func (ec *EventCollector) GetEventsByContainer(containerID string) []*Event {
	return ec.GetEvents(&EventFilter{
		ContainerID: containerID,
	})
}

// GetEventsByType retrieves events of a specific type
func (ec *EventCollector) GetEventsByType(eventType EventType) []*Event {
	return ec.GetEvents(&EventFilter{
		EventTypes: []EventType{eventType},
	})
}

// GetEventsBySeverity retrieves events with a specific severity
func (ec *EventCollector) GetEventsBySeverity(severity EventSeverity) []*Event {
	return ec.GetEvents(&EventFilter{
		Severities: []EventSeverity{severity},
	})
}

// GetRecentEvents retrieves recent events
func (ec *EventCollector) GetRecentEvents(count int) []*Event {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	if count > len(ec.events) {
		count = len(ec.events)
	}

	result := make([]*Event, count)
	start := len(ec.events) - count
	copy(result, ec.events[start:])
	return result
}

// GetStatistics returns collector statistics
func (ec *EventCollector) GetStatistics() *CollectorStats {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	// Return a copy
	statsCopy := *ec.stats
	return &statsCopy
}

// ClearEvents removes all events from the collector
func (ec *EventCollector) ClearEvents() {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.events = make([]*Event, 0, ec.maxEvents)
}

// GetEventCount returns the current number of stored events
func (ec *EventCollector) GetEventCount() int {
	ec.mu.RLock()
	defer ec.mu.RUnlock()
	return len(ec.events)
}

// SetRetentionDuration sets how long events are kept
func (ec *EventCollector) SetRetentionDuration(duration time.Duration) {
	ec.mu.Lock()
	defer ec.mu.Unlock()
	ec.retentionDuration = duration
}

// processEventQueue processes events from the queue
func (ec *EventCollector) processEventQueue() {
	for {
		select {
		case event := <-ec.eventChan:
			ec.handleEvent(event)
		case <-ec.stopChan:
			return
		}
	}
}

// handleEvent processes a single event through all registered processors
func (ec *EventCollector) handleEvent(event *Event) {
	// Run through processors
	ec.processorsLock.RLock()
	processors := make([]EventProcessor, len(ec.processors))
	copy(processors, ec.processors)
	ec.processorsLock.RUnlock()

	for _, processor := range processors {
		if err := processor(event); err != nil {
			ec.mu.Lock()
			ec.stats.FailedEvents++
			ec.mu.Unlock()
			return
		}
	}

	// Store event
	ec.mu.Lock()
	defer ec.mu.Unlock()

	ec.events = append(ec.events, event)

	// Maintain max event limit
	if len(ec.events) > ec.maxEvents {
		ec.events = ec.events[len(ec.events)-ec.maxEvents:]
	}

	// Update statistics
	ec.stats.TotalEvents++
	ec.stats.ProcessedEvents++
	ec.stats.EventsByType[event.Type]++
	ec.stats.EventsBySeverity[event.Severity]++
	ec.stats.LastEvent = event.Timestamp
}

// cleanupExpiredEvents periodically removes old events
func (ec *EventCollector) cleanupExpiredEvents() {
	ec.ticker = time.NewTicker(1 * time.Hour)
	defer ec.ticker.Stop()

	for {
		select {
		case <-ec.ticker.C:
			ec.removeExpiredEvents()
		case <-ec.stopChan:
			return
		}
	}
}

// removeExpiredEvents removes events older than retention duration
func (ec *EventCollector) removeExpiredEvents() {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	cutoffTime := time.Now().Add(-ec.retentionDuration)
	newEvents := make([]*Event, 0, len(ec.events))

	for _, event := range ec.events {
		if event.Timestamp.After(cutoffTime) {
			newEvents = append(newEvents, event)
		}
	}

	ec.events = newEvents
}

// matchesFilter checks if an event matches a filter
func (ec *EventCollector) matchesFilter(event *Event, filter *EventFilter) bool {
	if filter == nil {
		return true
	}

	// Check event types
	if len(filter.EventTypes) > 0 {
		found := false
		for _, et := range filter.EventTypes {
			if event.Type == et {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check sources
	if len(filter.Sources) > 0 {
		found := false
		for _, src := range filter.Sources {
			if event.Source == src {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check severities
	if len(filter.Severities) > 0 {
		found := false
		for _, sev := range filter.Severities {
			if event.Severity == sev {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Check container ID
	if filter.ContainerID != "" && event.ContainerID != filter.ContainerID {
		return false
	}

	// Check process name
	if filter.ProcessName != "" && event.ProcessName != filter.ProcessName {
		return false
	}

	// Check time range
	if filter.TimeRange != nil {
		if event.Timestamp.Before(filter.TimeRange.Start) || event.Timestamp.After(filter.TimeRange.End) {
			return false
		}
	}

	// Check tags
	if len(filter.Tags) > 0 {
		eventTagsMap := make(map[string]bool)
		for _, tag := range event.Tags {
			eventTagsMap[tag] = true
		}

		for _, filterTag := range filter.Tags {
			if !eventTagsMap[filterTag] {
				return false
			}
		}
	}

	return true
}

// generateEventID generates a unique event ID
func generateEventID() string {
	return fmt.Sprintf("evt-%d", time.Now().UnixNano())
}

// GetEventTimeline returns events grouped by time buckets
func (ec *EventCollector) GetEventTimeline(bucketSize time.Duration) map[time.Time][]EventType {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	timeline := make(map[time.Time][]EventType)

	for _, event := range ec.events {
		bucket := event.Timestamp.Truncate(bucketSize)
		timeline[bucket] = append(timeline[bucket], event.Type)
	}

	return timeline
}

// GetEventCorrelations finds related events by correlation ID
func (ec *EventCollector) GetEventCorrelations(correlationID string) []*Event {
	return ec.GetEvents(&EventFilter{})
}

// CorrelateEvents links related events together
func (ec *EventCollector) CorrelateEvents(eventID string, relatedEventID string) error {
	ec.mu.Lock()
	defer ec.mu.Unlock()

	var relatedEvent *Event
	for _, event := range ec.events {
		if event.ID == relatedEventID {
			relatedEvent = event
			break
		}
	}

	if relatedEvent == nil {
		return fmt.Errorf("related event not found: %s", relatedEventID)
	}

	for _, event := range ec.events {
		if event.ID == eventID {
			event.ParentEventID = relatedEventID
			return nil
		}
	}

	return fmt.Errorf("event not found: %s", eventID)
}

// GetEventChain returns a chain of related events
func (ec *EventCollector) GetEventChain(eventID string) []*Event {
	ec.mu.RLock()
	defer ec.mu.RUnlock()

	chain := make([]*Event, 0)
	visited := make(map[string]bool)

	var traverse func(id string)
	traverse = func(id string) {
		if visited[id] {
			return
		}
		visited[id] = true

		for _, event := range ec.events {
			if event.ID == id {
				chain = append(chain, event)
				if event.ParentEventID != "" {
					traverse(event.ParentEventID)
				}
				break
			}
		}
	}

	traverse(eventID)
	return chain
}

// ExportEvents exports events to a format suitable for external systems
func (ec *EventCollector) ExportEvents(filter *EventFilter) []map[string]interface{} {
	events := ec.GetEvents(filter)
	result := make([]map[string]interface{}, len(events))

	for i, event := range events {
		result[i] = map[string]interface{}{
			"id":              event.ID,
			"type":            string(event.Type),
			"source":          string(event.Source),
			"timestamp":       event.Timestamp,
			"process_id":      event.ProcessID,
			"container_id":    event.ContainerID,
			"process_name":    event.ProcessName,
			"user":            event.User,
			"hostname":        event.Hostname,
			"data":            event.Data,
			"severity":        string(event.Severity),
			"tags":            event.Tags,
			"correlation_id":  event.CorrelationID,
			"parent_event_id": event.ParentEventID,
		}
	}

	return result
}
