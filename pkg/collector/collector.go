package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
)

// EventType represents the type of event from eBPF
type EventType uint32

const (
	EventTypeExec    EventType = 0
	EventTypeNetStart EventType = 1
	EventTypeNetEnd   EventType = 2
	EventTypeFileOpen EventType = 3
	EventTypeFileWrite EventType = 4
	EventTypeLogWrite EventType = 5
)

// ExecEvent - Process execution event
type ExecEvent struct {
	PID        uint32    `json:"pid"`
	PPID       uint32    `json:"ppid"`
	CgroupID   uint64    `json:"cgroup_id"`
	Comm       string    `json:"comm"`
	Argv       string    `json:"argv"`
	Timestamp  uint64    `json:"timestamp_ns"`
	EventType  string    `json:"event_type"`
}

// NetEvent - Network connection event
type NetEvent struct {
	PID        uint32    `json:"pid"`
	CgroupID   uint64    `json:"cgroup_id"`
	Comm       string    `json:"comm"`
	SrcAddr    string    `json:"src_addr"`
	DstAddr    string    `json:"dst_addr"`
	DstPort    uint16    `json:"dst_port"`
	SrcPort    uint16    `json:"src_port"`
	Timestamp  uint64    `json:"timestamp_ns"`
	EventType  string    `json:"event_type"`
}

// FileEvent - File operation event
type FileEvent struct {
	PID        uint32    `json:"pid"`
	CgroupID   uint64    `json:"cgroup_id"`
	Comm       string    `json:"comm"`
	Path       string    `json:"path"`
	Flags      uint32    `json:"flags"`
	Timestamp  uint64    `json:"timestamp_ns"`
	EventType  string    `json:"event_type"`
}

// LogEvent - Stdout/stderr log event
type LogEvent struct {
	PID        uint32    `json:"pid"`
	CgroupID   uint64    `json:"cgroup_id"`
	Comm       string    `json:"comm"`
	FD         uint32    `json:"fd"`
	LogData    string    `json:"log_data"`
	LogSize    uint32    `json:"log_size"`
	Timestamp  uint64    `json:"timestamp_ns"`
	EventType  string    `json:"event_type"`
}

// eBPF object
type objects struct {
	ProcessTracker *ebpf.Program `ebpf:"trace_execve"`
	NetConnect     *ebpf.Program `ebpf:"trace_tcp_v4_connect"`
	NetClose       *ebpf.Program `ebpf:"trace_tcp_close"`
	FileOpen       *ebpf.Program `ebpf:"trace_openat"`
	FileWrite      *ebpf.Program `ebpf:"trace_write"`
	Events         *ebpf.Map     `ebpf:"events"`
	TrackedPids    *ebpf.Map     `ebpf:"tracked_pids"`
}

// Collector - Main event collector
type Collector struct {
	spec    *ebpf.CollectionSpec
	objs    *objects
	reader  *ringbuf.Reader
	eventCh chan json.RawMessage
}

// IP address formatting helper
func formatIP(ip uint32) string {
	// IP is in network byte order (big-endian)
	a := byte(ip >> 24)
	b := byte(ip >> 16)
	c := byte(ip >> 8)
	d := byte(ip)
	return fmt.Sprintf("%d.%d.%d.%d", a, b, c, d)
}

// Null-terminated string conversion
func cstrToString(b []byte) string {
	idx := bytes.IndexByte(b, 0)
	if idx == -1 {
		return string(b)
	}
	return string(b[:idx])
}

// NewCollector creates a new event collector
func NewCollector() (*Collector, error) {
	// Load eBPF objects
	objs := &objects{}
	spec, err := ebpf.LoadCollectionSpec("ebpf/tracer.o")
	if err != nil {
		return nil, fmt.Errorf("failed to load eBPF spec: %w", err)
	}

	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("failed to create eBPF collection: %w", err)
	}

	// TODO: Attach programs to kernel hooks in future iterations

	// Create ringbuf reader
	reader, err := ringbuf.NewReader(coll.Maps["events"])
	if err != nil {
		return nil, fmt.Errorf("failed to create ringbuf reader: %w", err)
	}

	return &Collector{
		spec:    spec,
		objs:    objs,
		reader:  reader,
		eventCh: make(chan json.RawMessage, 100),
	}, nil
}

// Start begins reading events from the ringbuf
func (c *Collector) Start(outputFile string) {
	go c.readEvents()

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Output file setup
	var outFile *os.File
	if outputFile != "" {
		f, err := os.Create(outputFile)
		if err != nil {
			log.Fatalf("Failed to create output file: %v", err)
		}
		defer f.Close()
		outFile = f
	} else {
		outFile = os.Stdout
	}

	fmt.Fprintf(outFile, "[*] Supply Tracer v%s - Monitoring package manager activity\n", Version)
	fmt.Fprintf(outFile, "[*] Press Ctrl+C to stop\n\n")

	eventCount := 0

	for {
		select {
		case <-sigChan:
			fmt.Fprintf(outFile, "\n[*] Stopping tracer... (%d events collected)\n", eventCount)
			return

		case rawEvent := <-c.eventCh:
			// Output event as JSON
			fmt.Fprintln(outFile, string(rawEvent))
			eventCount++
		}
	}
}

// readEvents reads events from the ringbuf
func (c *Collector) readEvents() {
	for {
		record, err := c.reader.Read()
		if err != nil {
			log.Printf("error reading record: %v", err)
			continue
		}

		// Parse raw event data
		if len(record.RawSample) < 1 {
			continue
		}

		eventType := record.RawSample[0]
		payload := record.RawSample[1:]

		var jsonEvent json.RawMessage
		var err error

		switch eventType {
		case 0:  // Exec event
			jsonEvent, err = parseExecEvent(payload)
		case 1:  // Net connect
			jsonEvent, err = parseNetEvent(payload, "tcp_connect")
		case 2:  // Net close
			jsonEvent, err = parseNetEvent(payload, "tcp_close")
		case 3:  // File open
			jsonEvent, err = parseFileEvent(payload, "file_open")
		case 4:  // File write
			jsonEvent, err = parseFileEvent(payload, "file_write")
		case 5:  // Log write
			jsonEvent, err = parseLogEvent(payload)
		default:
			continue
		}

		if err != nil {
			log.Printf("error parsing event: %v", err)
			continue
		}

		c.eventCh <- jsonEvent
	}
}

// Parse exec event from raw bytes
func parseExecEvent(data []byte) (json.RawMessage, error) {
	var event ExecEvent

	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &event.PID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.PPID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.CgroupID); err != nil {
		return nil, err
	}

	comm := make([]byte, 16)
	if _, err := buf.Read(comm); err != nil {
		return nil, err
	}
	event.Comm = cstrToString(comm)

	argv := make([]byte, 256)
	if _, err := buf.Read(argv); err != nil {
		return nil, err
	}
	event.Argv = cstrToString(argv)

	if err := binary.Read(buf, binary.LittleEndian, &event.Timestamp); err != nil {
		return nil, err
	}

	event.EventType = "exec"

	return json.Marshal(event)
}

// Parse network event from raw bytes
func parseNetEvent(data []byte, eventType string) (json.RawMessage, error) {
	var event NetEvent

	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &event.PID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.CgroupID); err != nil {
		return nil, err
	}

	comm := make([]byte, 16)
	if _, err := buf.Read(comm); err != nil {
		return nil, err
	}
	event.Comm = cstrToString(comm)

	var saddr, daddr uint32
	if err := binary.Read(buf, binary.LittleEndian, &saddr); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &daddr); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.DstPort); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.SrcPort); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.Timestamp); err != nil {
		return nil, err
	}

	event.SrcAddr = formatIP(saddr)
	event.DstAddr = formatIP(daddr)
	event.EventType = eventType

	return json.Marshal(event)
}

// Parse file event from raw bytes
func parseFileEvent(data []byte, eventType string) (json.RawMessage, error) {
	var event FileEvent

	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &event.PID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.CgroupID); err != nil {
		return nil, err
	}

	comm := make([]byte, 16)
	if _, err := buf.Read(comm); err != nil {
		return nil, err
	}
	event.Comm = cstrToString(comm)

	path := make([]byte, 256)
	if _, err := buf.Read(path); err != nil {
		return nil, err
	}
	event.Path = cstrToString(path)

	if err := binary.Read(buf, binary.LittleEndian, &event.Flags); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.Timestamp); err != nil {
		return nil, err
	}

	event.EventType = eventType

	return json.Marshal(event)
}

// Parse log event from raw bytes
func parseLogEvent(data []byte) (json.RawMessage, error) {
	var event LogEvent

	buf := bytes.NewReader(data)
	if err := binary.Read(buf, binary.LittleEndian, &event.PID); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.CgroupID); err != nil {
		return nil, err
	}

	comm := make([]byte, 16)
	if _, err := buf.Read(comm); err != nil {
		return nil, err
	}
	event.Comm = cstrToString(comm)

	if err := binary.Read(buf, binary.LittleEndian, &event.FD); err != nil {
		return nil, err
	}

	logData := make([]byte, 256)
	if _, err := buf.Read(logData); err != nil {
		return nil, err
	}

	if err := binary.Read(buf, binary.LittleEndian, &event.LogSize); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.Timestamp); err != nil {
		return nil, err
	}

	// Trim to actual size
	if event.LogSize < 256 {
		event.LogData = cstrToString(logData[:event.LogSize])
	} else {
		event.LogData = cstrToString(logData)
	}

	event.EventType = "log"

	return json.Marshal(event)
}

// Close closes the collector
func (c *Collector) Close() error {
	if c.reader != nil {
		return c.reader.Close()
	}
	return nil
}
