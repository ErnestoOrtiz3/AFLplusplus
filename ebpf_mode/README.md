# AFL++ eBPF Mode

This module provides eBPF-based instrumentation support for AFL++, allowing for efficient
kernel-level tracing and performance monitoring during fuzzing.

## Requirements

- Linux kernel 4.18+ with eBPF support
- libbpf development headers
- LLVM/Clang for BPF program compilation

## Building

The eBPF mode will be automatically built if your system has the required dependencies.
You can verify if eBPF support is enabled by checking for the `-DHAVE_EBPF` flag in the
build output.