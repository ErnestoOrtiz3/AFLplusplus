PWD:=$(shell pwd)/
ROOT:=$(PWD)../
BUILD_DIR:=$(PWD)build/

CFLAGS += -I$(ROOT)include -I$(ROOT)
CFLAGS += -g -O3 -funroll-loops -fPIC

all: test_deps
	@echo "[*] Building eBPF module"
	@install -d $(BUILD_DIR)
	$(CC) $(CFLAGS) -c src/ebpf.c -o $(BUILD_DIR)ebpf.o
	@echo "[*] Creating symbolic link to ebpf.o"
	ln -sf $(BUILD_DIR)ebpf.o ../ebpf.o || { echo "[-] Failed to create symbolic link"; exit 1; }
	@echo "[+] eBPF module built successfully"

.PHONY: test_deps
test_deps:
	@echo "[*] Checking for eBPF support"
	@if [ "$(HAS_EBPF)" = "0" ]; then \
		echo "[-] eBPF support not found"; \
		exit 1; \
	fi
	@echo "[+] eBPF support found"

clean:
	@echo "[*] Cleaning eBPF module"
	@rm -rf $(BUILD_DIR)
	@rm -f ../ebpf.o
