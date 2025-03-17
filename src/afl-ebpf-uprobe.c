// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Required GPL license for eBPF programs
char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u64);
} test_runs SEC(".maps");

// Attach to the entry point of the target's main function
// Note: We'll need to replace TARGET_BINARY with the actual binary name
SEC("uprobe/TARGET_BINARY:main")
int trace_target_entry(struct pt_regs *ctx) {
    __u32 key = 0;
    __u64 *count;
    
    count = bpf_map_lookup_elem(&test_runs, &key);
    if (count) {
        // Atomically increment the counter
        __sync_fetch_and_add(count, 1);
    }
    
    return 0;
}