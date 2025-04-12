# AFL++ CPU Scheduler Makefile

# Compiler and flags
CC = gcc
CFLAGS = -Wall -Werror -O2
LDFLAGS = -lbpf -lelf

# BPF compiler
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

# SCX path - adjust this to point to your SCX installation
SCX_PATH ?= ../scx

# Source files
MONITOR_SRC = afl_monitor.c
SCHED_SRC = afl_sched.c
BPF_SRC = bpf/afl_sched.bpf.c

# Output files
MONITOR_BIN = afl_monitor
SCHED_BIN = afl_sched
BPF_OBJ = bpf/afl_sched.bpf.o
SKEL_H = afl_sched.skel.h

# Default target
all: $(MONITOR_BIN) $(SCHED_BIN) stats_collector

# Build monitor daemon
$(MONITOR_BIN): $(MONITOR_SRC)
	$(CC) $(CFLAGS) -o $@ $< -lm

# Build BPF object file
$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) -g -O2 -target bpf \
		-D__TARGET_ARCH_x86 \
		-I$(SCX_PATH) \
		-I$(SCX_PATH)/scheds/include \
		-c $(BPF_SRC) -o $@
	$(LLVM_STRIP) -g $@

# Generate skeleton header
$(SKEL_H): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# Build scheduler
$(SCHED_BIN): $(SCHED_SRC) $(SKEL_H)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Add stats collector to build targets
stats_collector: stats_collector.c
	$(CC) -o $@ $< -lbpf

# Clean
clean:
	rm -f $(MONITOR_BIN) $(SCHED_BIN) $(BPF_OBJ) $(SKEL_H) stats_collector

# Install
install: all
	install -m 755 $(MONITOR_BIN) /usr/local/bin/
	install -m 755 $(SCHED_BIN) /usr/local/bin/
	install -m 755 stats_collector /usr/local/bin/

.PHONY: all clean install
