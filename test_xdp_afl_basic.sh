#!/bin/bash
# Basic test script for XDP AFL implementation

set -e

# Compile XDP program
echo "Compiling XDP program..."
clang -O2 -target bpf -I/usr/include/$(uname -m)-linux-gnu -c xdp_afl_pass.c -o xdp_afl_pass.o

# Compile loader
echo "Compiling loader..."
gcc -Wall -o xdp_afl_loader xdp_afl_loader.c -lbpf -lelf -I/usr/include/$(uname -m)-linux-gnu -I/usr/include/libbpf

# Run basic connectivity test
echo "Testing basic connectivity..."
ping -c 3 127.0.0.1 > /dev/null
if [ $? -ne 0 ]; then
    echo "ERROR: Basic connectivity test failed"
    exit 1
fi

# Attach XDP program to loopback interface
echo "Attaching XDP program to lo interface..."
./xdp_afl_loader lo xdp_afl_pass.o &
LOADER_PID=$!
sleep 2

# Test connectivity with XDP attached
echo "Testing connectivity with XDP attached..."
ping -c 3 127.0.0.1 > /dev/null
RESULT=$?

# Kill loader and detach XDP program
kill $LOADER_PID
wait $LOADER_PID 2>/dev/null || true

if [ $RESULT -ne 0 ]; then
    echo "ERROR: Connectivity test with XDP attached failed"
    exit 1
fi

echo "Basic XDP test passed successfully!"
exit 0
