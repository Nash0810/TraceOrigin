# eBPF Build Makefile
# Requires: clang, llvm, libbpf

CLANG ?= clang
LLC ?= llc
STRIP ?= llvm-strip
VMLINUX_BTF ?= /sys/kernel/btf/vmlinux

INCLUDES := -I/usr/include/bpf
CFLAGS := -O2 -target bpf -D__KERNEL__ -D__BPF_TRACING__ $(INCLUDES)
# Add -g to include debugging info (which includes BTF)
CFLAGS += -g

# Source files
EBPF_SOURCES := $(wildcard *.c)
EBPF_OBJECTS := $(EBPF_SOURCES:.c=.o)

.PHONY: all clean vmlinux.h

all: vmlinux.h $(EBPF_OBJECTS)

vmlinux.h:
	@echo "[*] Generating vmlinux.h from kernel BTF..."
	@if [ -f "$(VMLINUX_BTF)" ]; then \
		bpftool btf dump file $(VMLINUX_BTF) format c > vmlinux.h; \
		echo "[+] vmlinux.h generated"; \
	else \
		echo "[!] WARNING: $(VMLINUX_BTF) not found"; \
		echo "[!] Install linux-headers or run: apt-get install linux-headers-\$$(uname -r)"; \
		echo "[!] Creating minimal vmlinux.h stub..."; \
		touch vmlinux.h; \
	fi

%.o: %.c vmlinux.h
	@echo "[*] Compiling $< with BTF..."
	@$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "[+] Built $@"

clean:
	@echo "[*] Cleaning eBPF artifacts..."
	@rm -f *.o vmlinux.h
	@echo "[+] Clean complete"

help:
	@echo "eBPF Build System"
	@echo "Targets:"
	@echo "  all       - Build all eBPF programs (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  vmlinux.h - Generate vmlinux.h from kernel BTF"
	@echo "  help      - Show this help"

