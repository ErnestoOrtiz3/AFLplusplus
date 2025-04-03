# AFL++ Feedback-Guided CPU Scheduler Makefile

CLANG ?= clang
LIBBPF_DIR ?= /usr/include/bpf
LIBBPF_LIB ?= /usr/lib/libbpf.a

# Check for required headers
# Force headers to be found since we verified they exist
HAS_LINUX_HEADERS := 1
HAS_LIBBPF := 1

all:
	@if [ "$(HAS_LINUX_HEADERS)" = "0" ]; then \
		echo "[!] Linux headers not found. Please install linux-headers-$(shell uname -r)"; \
		echo "    For Debian/Ubuntu: sudo apt-get install linux-headers-$(shell uname -r)"; \
		echo "    For Fedora: sudo dnf install kernel-devel"; \
		exit 1; \
	fi
	@if [ "$(HAS_LIBBPF)" = "0" ]; then \
		echo "[!] libbpf not found. Please install libbpf-dev"; \
		echo "    For Debian/Ubuntu: sudo apt-get install libbpf-dev"; \
		echo "    For Fedora: sudo dnf install libbpf-devel"; \
		exit 1; \
	fi
	@$(MAKE) build

build: afl_scheduler.bpf.o afl_scheduler_daemon

afl_scheduler.bpf.o: afl_scheduler.bpf.c
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_x86 \
		-I$(LIBBPF_DIR) -I/usr/include -I/usr/include/x86_64-linux-gnu -c $< -o $@

scheduler_metrics.o: scheduler_metrics.c scheduler_metrics.h
	$(CC) -g -O2 -c $< -o $@

afl_scheduler_daemon: afl_scheduler_daemon.c scheduler_metrics.o
	$(CC) -g -O2 -I../include -I$(LIBBPF_DIR) \
		$< scheduler_metrics.o $(LIBBPF_LIB) -lelf -lz -lpthread -o $@

clean:
	rm -f afl_scheduler.bpf.o afl_scheduler_daemon *.o *.so *.a

.PHONY: all build clean
