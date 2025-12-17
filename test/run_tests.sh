#!/bin/bash
# Test suite for Supply Tracer
# Requires: root privileges, docker

set -e

echo "[*] Supply Tracer Integration Test Suite"
echo "[*] Note: Requires root privileges and Docker"
echo ""

# Check for root
if [ "$EUID" -ne 0 ]; then
    echo "[!] This script must be run with sudo"
    exit 1
fi

# Check for required tools
for tool in docker clang llvm; do
    if ! command -v $tool &> /dev/null; then
        echo "[!] Required tool not found: $tool"
        exit 1
    fi
done

echo "[+] All prerequisites found"
echo ""

# Test 1: Build eBPF
echo "[*] Test 1: Building eBPF programs..."
cd ../.. && make build-ebpf
echo "[+] Test 1 passed"
echo ""

# Test 2: Build Go binary
echo "[*] Test 2: Building Go binary..."
make build-go
echo "[+] Test 2 passed"
echo ""

echo "[+] All integration tests passed!"
