# AFL++ Scheduler Makefile

# Compiler and flags
CC = gcc
CFLAGS = -g -O2 -Wall -Werror
LDFLAGS = -lbpf -lelf

# BPF compiler
CLANG ?= clang

# Kernel headers
KERNEL_HEADERS ?= /usr/src/linux-headers-$(shell uname -r)
LIBBPF_HEADERS ?= /usr/include/bpf

CFLAGS_BPF = -g -O2 -target bpf -D__TARGET_ARCH_x86 \
	-I$(KERNEL_HEADERS)/arch/x86/include \
	-I$(KERNEL_HEADERS)/arch/x86/include/generated \
	-I$(KERNEL_HEADERS)/include \
	-I$(KERNEL_HEADERS)/arch/x86/include/uapi \
	-I$(KERNEL_HEADERS)/arch/x86/include/generated/uapi \
	-I$(KERNEL_HEADERS)/include/uapi \
	-I$(KERNEL_HEADERS)/include/generated/uapi \
	-I$(LIBBPF_HEADERS)

# Source files
SRC = afl_scheduler.c
BPF_SRC = afl_scheduler.bpf.c
OBJ = $(SRC:.c=.o)
BPF_OBJ = $(BPF_SRC:.c=.o)

# Output files
PROG = afl_scheduler
SKEL = afl_scheduler.skel.h

# Default target
all: $(PROG)

# Generate BPF skeleton
$(SKEL): $(BPF_OBJ)
	bpftool gen skeleton $< > $@

# Compile BPF program
$(BPF_OBJ): $(BPF_SRC)
	$(CLANG) $(CFLAGS_BPF) -c $< -o $@

# Compile user-space program
$(OBJ): $(SRC) $(SKEL)
	$(CC) $(CFLAGS) -c $< -o $@

# Link user-space program
$(PROG): $(OBJ)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Clean up
clean:
	rm -f $(PROG) $(OBJ) $(BPF_OBJ) $(SKEL)

.PHONY: all clean
