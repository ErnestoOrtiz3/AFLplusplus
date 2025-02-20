#!/bin/sh

. ./test-pre.sh

# Run all the other tests first
./test-basic.sh
./test-llvm.sh
./test-gcc-plugin.sh
./test-frida-mode.sh
./test-custom-mutators.sh
./test-performance.sh
# Add eBPF test
./test-ebpf.sh

exit 0
