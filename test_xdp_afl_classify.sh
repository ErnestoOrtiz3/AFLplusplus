#!/bin/bash
# Test script for XDP AFL classification implementation

set -e

# Default ports to monitor
AFL_PORTS="8080 9000"

# Check if BTF is available
if [ -e /sys/kernel/btf/vmlinux ]; then
    echo "BTF is available. Using standard XDP program."
    XDP_PROGRAM="xdp_afl_classify.c"
    XDP_OBJECT="xdp_afl_classify.o"
else
    echo "WARNING: BTF not available. Using simplified XDP program."
    XDP_PROGRAM="xdp_afl_classify_simple.c"
    XDP_OBJECT="xdp_afl_classify_simple.o"
fi

# Compile XDP program with BTF support
echo "Compiling XDP program..."
clang -O2 -g -target bpf -I/usr/include/$(uname -m)-linux-gnu -c $XDP_PROGRAM -o $XDP_OBJECT

# Verify the compiled object
echo "Verifying compiled XDP object..."
if ! llvm-objdump -h $XDP_OBJECT 2>/dev/null | grep -q ".BTF"; then
    echo "WARNING: BTF section not found in compiled object. Using simplified loader approach."
    LOADER_OPTS="--no-btf"
else
    echo "BTF section found in compiled object."
    LOADER_OPTS=""
fi

# Compile loader with pkg-config
echo "Compiling loader..."
gcc -Wall -o xdp_afl_loader_classify xdp_afl_loader_classify.c $(pkg-config --cflags --libs libbpf)

# Run basic connectivity test
echo "Testing basic connectivity..."
ping -c 3 127.0.0.1 > /dev/null
if [ $? -ne 0 ]; then
    echo "ERROR: Basic connectivity test failed"
    exit 1
fi

# Attach XDP program to loopback interface
echo "Attaching XDP program to lo interface with AFL ports: $AFL_PORTS..."
sudo ./xdp_afl_loader_classify lo $XDP_OBJECT $LOADER_OPTS $AFL_PORTS

echo "XDP classifier is running. Press Ctrl+C to stop."
