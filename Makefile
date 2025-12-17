.PHONY: all build build-ebpf build-go test clean install lint help

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-X main.Version=$(VERSION)"
BINARY_NAME := supply-tracer

# Build targets
all: build

help:
	@echo "TraceOrigin - Container Supply Chain Tracer"
	@echo ""
	@echo "Available targets:"
	@echo "  build         - Build eBPF programs and Go binary"
	@echo "  build-ebpf    - Build eBPF programs only"
	@echo "  build-go      - Build Go binary only"
	@echo "  test          - Run Go unit tests"
	@echo "  test-integration - Run integration tests (requires root)"
	@echo "  clean         - Remove build artifacts"
	@echo "  install       - Install binary to /usr/local/bin (requires root)"
	@echo "  lint          - Run linters"
	@echo "  help          - Show this help message"

build-ebpf:
	@echo "[*] Building eBPF programs..."
	@cd ebpf && make
	@echo "[+] eBPF programs built successfully"

build-go: build-ebpf
	@echo "[*] Building Go binary..."
	@go build $(LDFLAGS) -o bin/$(BINARY_NAME) cmd/tracer/main.go
	@echo "[+] Go binary built successfully: bin/$(BINARY_NAME)"

build: build-go

test:
	@echo "[*] Running unit tests..."
	@go test ./... -v -cover
	@echo "[+] Tests passed"

test-integration: build
	@echo "[*] Running integration tests..."
	@echo "WARNING: Integration tests require root privileges"
	@bash test/run_tests.sh

clean:
	@echo "[*] Cleaning build artifacts..."
	@rm -rf bin/
	@cd ebpf && make clean
	@go clean
	@echo "[+] Clean complete"

install: build
	@echo "[*] Installing to /usr/local/bin..."
	@sudo cp bin/$(BINARY_NAME) /usr/local/bin/
	@sudo mkdir -p /etc/supply-tracer
	@sudo cp ebpf/*.o /etc/supply-tracer/ 2>/dev/null || true
	@echo "[+] Installation complete"

lint:
	@echo "[*] Running linters..."
	@go fmt ./...
	@go vet ./...
	@echo "[+] Linting complete"

fmt:
	@go fmt ./...
	@cd ebpf && clang-format -i *.c 2>/dev/null || echo "clang-format not found (optional)"

.SILENT: help
