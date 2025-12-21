package collector

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
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"

	"github.com/Nash0810/TraceOrigin/pkg/container"
)

// KernelEventType represents the type of event from eBPF kernel
type KernelEventType uint32

const (
	KernelEventTypeExec    KernelEventType = 0
	KernelEventTypeNetStart KernelEventType = 1
	KernelEventTypeNetEnd   KernelEventType = 2
	KernelEventTypeFileOpen KernelEventType = 3
	KernelEventTypeFileWrite KernelEventType = 4
	KernelEventTypeLogWrite KernelEventType = 5
	KernelEventTypeHTTP     KernelEventType = 6
)

// ExecEvent - Process execution event
type ExecEvent struct {
	PID        uint32    `json:"pid"`
	PPID       uint32    `json:"ppid"`
	CgroupID   uint64    `json:"cgroup_id"`
	ContainerID string   `json:"container_id"`
	Comm       string    `json:"comm"`
	Argv       string    `json:"argv"`
	Timestamp  uint64    `json:"timestamp_ns"`
	EventType  string    `json:"event_type"`
}

// NetEvent - Network connection event
type NetEvent struct {
	PID        uint32    `json:"pid"`
	CgroupID   uint64    `json:"cgroup_id"`
	ContainerID string   `json:"container_id"`
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
	ContainerID string   `json:"container_id"`
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
	ContainerID string   `json:"container_id"`
	Comm       string    `json:"comm"`
	FD         uint32    `json:"fd"`
	LogData    string    `json:"log_data"`
	LogSize    uint32    `json:"log_size"`
	Timestamp  uint64    `json:"timestamp_ns"`
	EventType  string    `json:"event_type"`
}

// HTTPEvent - HTTP request event
type HTTPEvent struct {
	PID         uint32    `json:"pid"`
	CgroupID    uint64    `json:"cgroup_id"`
	ContainerID string    `json:"container_id"`
	Comm        string    `json:"comm"`
	URL         string    `json:"url"`
	Host        string    `json:"host"`
	Method      uint32    `json:"method"`
	Timestamp   uint64    `json:"timestamp_ns"`
	EventType   string    `json:"event_type"`
}

// eBPF object
type objects struct {
	ProcessTracker *ebpf.Program `ebpf:"trace_execve"`
	NetConnect     *ebpf.Program `ebpf:"trace_tcp_v4_connect"`
	NetClose       *ebpf.Program `ebpf:"trace_tcp_close"`
	FileOpen       *ebpf.Program `ebpf:"trace_openat"`
	FileWrite      *ebpf.Program `ebpf:"trace_write"`
	HTTPSend       *ebpf.Program `ebpf:"trace_http_send"`
	Events         *ebpf.Map     `ebpf:"events"`
	TrackedPids    *ebpf.Map     `ebpf:"tracked_pids"`
}

// Collector - Main event collector
type Collector struct {
	spec           *ebpf.CollectionSpec
	objs           *objects
	reader         *ringbuf.Reader
	eventCh        chan json.RawMessage
	resolver       *container.ContainerResolver
	syntheticMode  bool  // If true, generate synthetic data for MVP testing
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
	// Load all eBPF programs from individual .o files
	// Each .o file has its own maps, so we create them once and share
	
	programs := make(map[string]*ebpf.Program)
	var sharedEvents *ebpf.Map
	var sharedTrackedPids *ebpf.Map
	
	programFiles := []string{
		"process_tracker",
		"network_tracker", 
		"file_tracker",
		"http_parser",
	}

	for _, name := range programFiles {
		objPath := fmt.Sprintf("ebpf/%s.o", name)
		spec, err := ebpf.LoadCollectionSpec(objPath)
		if err != nil {
			log.Printf("warning: failed to load %s: %v", objPath, err)
			continue
		}

		// Create collection for this program
		coll, err := ebpf.NewCollection(spec)
		if err != nil {
			log.Printf("warning: failed to create collection for %s: %v", name, err)
			continue
		}

		// Store first maps we encounter (they should all be the same by name)
		if sharedEvents == nil {
			sharedEvents = coll.Maps["events"]
		}
		if sharedTrackedPids == nil {
			sharedTrackedPids = coll.Maps["tracked_pids"]
		}

		// Store programs by their function names
		for progName, prog := range coll.Programs {
			programs[progName] = prog
		}
	}

	if sharedEvents == nil {
		log.Printf("[!] No eBPF programs loaded successfully")
		log.Printf("[!] Falling back to synthetic data mode for MVP testing")
		return &Collector{
			spec:          nil,
			objs:          &objects{},
			reader:        nil,
			eventCh:       make(chan json.RawMessage, 100),
			resolver:      container.NewContainerResolver(),
			syntheticMode: true,
		}, nil
	}

	// Create ringbuf reader
	reader, err := ringbuf.NewReader(sharedEvents)
	if err != nil {
		return nil, fmt.Errorf("failed to create ringbuf reader: %w", err)
	}

	// Attach programs to kernel hooks
	attachedCount := 0

	// Process tracker - trace_execve
	if prog, ok := programs["trace_execve"]; ok {
		kp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
		if err != nil {
			log.Printf("warning: failed to attach trace_execve: %v", err)
		} else {
			log.Printf("[+] Attached trace_execve")
			attachedCount++
			_ = kp
		}
	}

	// File tracker - track_package_manager
	if prog, ok := programs["track_package_manager"]; ok {
		kp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
		if err != nil {
			log.Printf("warning: failed to attach track_package_manager: %v", err)
		} else {
			log.Printf("[+] Attached track_package_manager")
			attachedCount++
			_ = kp
		}
	}

	// HTTP parser - track_pm_http
	if prog, ok := programs["track_pm_http"]; ok {
		kp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
		if err != nil {
			log.Printf("warning: failed to attach track_pm_http: %v", err)
		} else {
			log.Printf("[+] Attached track_pm_http")
			attachedCount++
			_ = kp
		}
	}

	// Network tracker - kprobes
	if prog, ok := programs["trace_tcp_v4_connect"]; ok {
		kp, err := link.Kprobe("tcp_v4_connect", prog, nil)
		if err != nil {
			log.Printf("warning: failed to attach trace_tcp_v4_connect: %v", err)
		} else {
			log.Printf("[+] Attached trace_tcp_v4_connect")
			attachedCount++
			_ = kp
		}
	}

	if prog, ok := programs["trace_tcp_close"]; ok {
		kp, err := link.Kprobe("tcp_close", prog, nil)
		if err != nil {
			log.Printf("warning: failed to attach trace_tcp_close: %v", err)
		} else {
			log.Printf("[+] Attached trace_tcp_close")
			attachedCount++
			_ = kp
		}
	}

	if prog, ok := programs["trace_sched_exec"]; ok {
		kp, err := link.Tracepoint("syscalls", "sys_enter_execve", prog, nil)
		if err != nil {
			log.Printf("warning: failed to attach trace_sched_exec: %v", err)
		} else {
			log.Printf("[+] Attached trace_sched_exec")
			attachedCount++
			_ = kp
		}
	}

	// HTTP sender
	if prog, ok := programs["trace_http_send"]; ok {
		kp, err := link.Kprobe("tcp_sendmsg", prog, nil)
		if err != nil {
			log.Printf("warning: failed to attach trace_http_send: %v", err)
		} else {
			log.Printf("[+] Attached trace_http_send")
			attachedCount++
			_ = kp
		}
	}

	if attachedCount == 0 {
		log.Printf("[!] No eBPF programs were successfully attached")
		log.Printf("[!] Falling back to synthetic data mode for MVP testing")
	}

	return &Collector{
		spec:          nil,
		objs:          &objects{},
		reader:        reader,
		eventCh:       make(chan json.RawMessage, 100),
		resolver:      container.NewContainerResolver(),
		syntheticMode: attachedCount == 0,  // Enable synthetic if no programs attached
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

	fmt.Fprintf(outFile, "[*] Supply Tracer - Monitoring package manager activity\n")
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

// readEvents reads events from the ringbuf or generates synthetic data
func (c *Collector) readEvents() {
	if c.syntheticMode {
		c.readSyntheticEvents()
		return
	}

	for {
		if c.reader == nil {
			time.Sleep(1 * time.Second)
			continue
		}

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
		var parseErr error

		switch eventType {
		case 0:  // Exec event
			jsonEvent, parseErr = c.parseExecEvent(payload)
		case 1:  // Net connect
			jsonEvent, parseErr = c.parseNetEvent(payload, "tcp_connect")
		case 2:  // Net close
			jsonEvent, parseErr = c.parseNetEvent(payload, "tcp_close")
		case 3:  // File open
			jsonEvent, parseErr = c.parseFileEvent(payload, "file_open")
		case 4:  // File write
			jsonEvent, parseErr = c.parseFileEvent(payload, "file_write")
		case 5:  // Log write
			jsonEvent, parseErr = c.parseLogEvent(payload)
		case 6:  // HTTP request
			jsonEvent, parseErr = c.parseHTTPEvent(payload)
		default:
			continue
		}

		if parseErr != nil {
			log.Printf("error parsing event: %v", parseErr)
			continue
		}

		c.eventCh <- jsonEvent
	}
}

// readSyntheticEvents generates demo/synthetic events for MVP testing
// This allows testing the correlation and SBOM generation pipeline without real eBPF
// Now supports multiple package managers: pip, npm, go, bundle
func (c *Collector) readSyntheticEvents() {
	baseTime := time.Now().UnixNano()
	syntheticEvents := []map[string]interface{}{
		// ═══════════════════════════════════════════════════════════
		// PYTHON: pip install
		// ═══════════════════════════════════════════════════════════
		
		// Process execution: pip install
		{
			"event_type": "exec",
			"pid": 1234,
			"ppid": 1000,
			"cgroup_id": 4294967296,
			"container_id": "abc123def456",
			"comm": "pip",
			"argv": "pip install flask==2.3.0 requests==2.31.0 numpy==1.24.3",
			"timestamp_ns": baseTime,
		},
		// Network connection to PyPI
		{
			"event_type": "tcp_connect",
			"pid": 1234,
			"cgroup_id": 4294967296,
			"container_id": "abc123def456",
			"comm": "pip",
			"src_addr": "172.17.0.2",
			"dst_addr": "151.101.108.133",  // pythonhosted.org
			"dst_port": 443,
			"src_port": 54321,
			"timestamp_ns": baseTime + 1000000,
		},
		// Log: Successfully installed flask
		{
			"event_type": "log",
			"pid": 1234,
			"cgroup_id": 4294967296,
			"container_id": "abc123def456",
			"comm": "pip",
			"fd": 1,
			"log_data": "Successfully installed flask==2.3.0",
			"timestamp_ns": baseTime + 2000000,
		},
		// Log: Successfully installed requests
		{
			"event_type": "log",
			"pid": 1234,
			"cgroup_id": 4294967296,
			"container_id": "abc123def456",
			"comm": "pip",
			"fd": 1,
			"log_data": "Successfully installed requests==2.31.0",
			"timestamp_ns": baseTime + 3000000,
		},
		// Log: Successfully installed numpy
		{
			"event_type": "log",
			"pid": 1234,
			"cgroup_id": 4294967296,
			"container_id": "abc123def456",
			"comm": "pip",
			"fd": 1,
			"log_data": "Successfully installed numpy==1.24.3",
			"timestamp_ns": baseTime + 4000000,
		},

		// ═══════════════════════════════════════════════════════════
		// NODEJS: npm install
		// ═══════════════════════════════════════════════════════════

		// Process execution: npm install
		{
			"event_type": "exec",
			"pid": 1235,
			"ppid": 1001,
			"cgroup_id": 4294967297,
			"container_id": "def456ghi789",
			"comm": "npm",
			"argv": "npm install express@4.18.0 axios@1.4.0 lodash@4.17.21",
			"timestamp_ns": baseTime + 5000000,
		},
		// Network connection to npm registry
		{
			"event_type": "tcp_connect",
			"pid": 1235,
			"cgroup_id": 4294967297,
			"container_id": "def456ghi789",
			"comm": "npm",
			"src_addr": "172.17.0.3",
			"dst_addr": "151.101.1.225",  // registry.npmjs.org
			"dst_port": 443,
			"src_port": 54322,
			"timestamp_ns": baseTime + 6000000,
		},
		// Log: added express
		{
			"event_type": "log",
			"pid": 1235,
			"cgroup_id": 4294967297,
			"container_id": "def456ghi789",
			"comm": "npm",
			"fd": 1,
			"log_data": "added express@4.18.0",
			"timestamp_ns": baseTime + 7000000,
		},
		// Log: added axios
		{
			"event_type": "log",
			"pid": 1235,
			"cgroup_id": 4294967297,
			"container_id": "def456ghi789",
			"comm": "npm",
			"fd": 1,
			"log_data": "added axios@1.4.0",
			"timestamp_ns": baseTime + 8000000,
		},
		// Log: added lodash
		{
			"event_type": "log",
			"pid": 1235,
			"cgroup_id": 4294967297,
			"container_id": "def456ghi789",
			"comm": "npm",
			"fd": 1,
			"log_data": "added lodash@4.17.21",
			"timestamp_ns": baseTime + 9000000,
		},

		// ═══════════════════════════════════════════════════════════
		// GO: go get
		// ═══════════════════════════════════════════════════════════

		// Process execution: go get
		{
			"event_type": "exec",
			"pid": 1236,
			"ppid": 1002,
			"cgroup_id": 4294967298,
			"container_id": "ghi789jkl012",
			"comm": "go",
			"argv": "go get github.com/gin-gonic/gin@v1.9.1 github.com/sirupsen/logrus@v1.9.3",
			"timestamp_ns": baseTime + 10000000,
		},
		// Network connection to proxy.golang.org
		{
			"event_type": "tcp_connect",
			"pid": 1236,
			"cgroup_id": 4294967298,
			"container_id": "ghi789jkl012",
			"comm": "go",
			"src_addr": "172.17.0.4",
			"dst_addr": "142.251.41.14",  // proxy.golang.org
			"dst_port": 443,
			"src_port": 54323,
			"timestamp_ns": baseTime + 11000000,
		},
		// Log: go module gin-gonic/gin
		{
			"event_type": "log",
			"pid": 1236,
			"cgroup_id": 4294967298,
			"container_id": "ghi789jkl012",
			"comm": "go",
			"fd": 1,
			"log_data": "go: added github.com/gin-gonic/gin v1.9.1",
			"timestamp_ns": baseTime + 12000000,
		},
		// Log: go module logrus
		{
			"event_type": "log",
			"pid": 1236,
			"cgroup_id": 4294967298,
			"container_id": "ghi789jkl012",
			"comm": "go",
			"fd": 1,
			"log_data": "go: added github.com/sirupsen/logrus v1.9.3",
			"timestamp_ns": baseTime + 13000000,
		},

		// ═══════════════════════════════════════════════════════════
		// RUBY: bundle install
		// ═══════════════════════════════════════════════════════════

		// Process execution: bundle install
		{
			"event_type": "exec",
			"pid": 1237,
			"ppid": 1003,
			"cgroup_id": 4294967299,
			"container_id": "jkl012mno345",
			"comm": "bundle",
			"argv": "bundle install",
			"timestamp_ns": baseTime + 14000000,
		},
		// Network connection to rubygems.org
		{
			"event_type": "tcp_connect",
			"pid": 1237,
			"cgroup_id": 4294967299,
			"container_id": "jkl012mno345",
			"comm": "bundle",
			"src_addr": "172.17.0.5",
			"dst_addr": "151.101.193.70",  // rubygems.org
			"dst_port": 443,
			"src_port": 54324,
			"timestamp_ns": baseTime + 15000000,
		},
		// Log: Successfully installed nokogiri
		{
			"event_type": "log",
			"pid": 1237,
			"cgroup_id": 4294967299,
			"container_id": "jkl012mno345",
			"comm": "bundle",
			"fd": 1,
			"log_data": "Successfully installed nokogiri-1.14.0",
			"timestamp_ns": baseTime + 16000000,
		},
		// Log: Successfully installed rails
		{
			"event_type": "log",
			"pid": 1237,
			"cgroup_id": 4294967299,
			"container_id": "jkl012mno345",
			"comm": "bundle",
			"fd": 1,
			"log_data": "Successfully installed rails-7.0.4",
			"timestamp_ns": baseTime + 17000000,
		},
	}

	// Send synthetic events
	for _, evt := range syntheticEvents {
		data, err := json.Marshal(evt)
		if err != nil {
			log.Printf("error marshaling synthetic event: %v", err)
			continue
		}
		c.eventCh <- json.RawMessage(data)
		time.Sleep(100 * time.Millisecond)  // Stagger events
	}

	// Keep the channel alive - user will Ctrl+C when done
	select {}
}

// Parse exec event from raw bytes
func (c *Collector) parseExecEvent(data []byte) (json.RawMessage, error) {
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

	// Resolve container ID LIVE while event is fresh
	event.ContainerID = c.resolver.ResolveCgroupID(event.CgroupID)

	event.EventType = "exec"

	return json.Marshal(event)
}

// Parse network event from raw bytes
func (c *Collector) parseNetEvent(data []byte, eventType string) (json.RawMessage, error) {
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

	// Resolve container ID LIVE
	event.ContainerID = c.resolver.ResolveCgroupID(event.CgroupID)

	event.SrcAddr = formatIP(saddr)
	event.DstAddr = formatIP(daddr)
	event.EventType = eventType

	return json.Marshal(event)
}

// Parse file event from raw bytes
func (c *Collector) parseFileEvent(data []byte, eventType string) (json.RawMessage, error) {
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

	// Resolve container ID LIVE
	event.ContainerID = c.resolver.ResolveCgroupID(event.CgroupID)

	event.EventType = eventType

	return json.Marshal(event)
}

// Parse log event from raw bytes
func (c *Collector) parseLogEvent(data []byte) (json.RawMessage, error) {
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

	// Resolve container ID LIVE
	event.ContainerID = c.resolver.ResolveCgroupID(event.CgroupID)

	// Trim to actual size
	if event.LogSize < 256 {
		event.LogData = cstrToString(logData[:event.LogSize])
	} else {
		event.LogData = cstrToString(logData)
	}

	event.EventType = "log"

	return json.Marshal(event)
}

// Parse HTTP event from raw bytes
func (c *Collector) parseHTTPEvent(data []byte) (json.RawMessage, error) {
	var event HTTPEvent

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

	url := make([]byte, 256)
	if _, err := buf.Read(url); err != nil {
		return nil, err
	}
	event.URL = cstrToString(url)

	host := make([]byte, 128)
	if _, err := buf.Read(host); err != nil {
		return nil, err
	}
	event.Host = cstrToString(host)

	if err := binary.Read(buf, binary.LittleEndian, &event.Timestamp); err != nil {
		return nil, err
	}
	if err := binary.Read(buf, binary.LittleEndian, &event.Method); err != nil {
		return nil, err
	}

	// Resolve container ID LIVE
	event.ContainerID = c.resolver.ResolveCgroupID(event.CgroupID)

	event.EventType = "http"

	return json.Marshal(event)
}
