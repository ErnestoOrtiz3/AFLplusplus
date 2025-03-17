// SPDX-License-Identifier: GPL-2.0-only
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/ptrace.h>

// Define BPF map to store execution count
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);    // Array type map
    __uint(max_entries, 1);              // Single element array
    __type(key, __u32);                  // Key type: 32-bit unsigned int
    __type(value, __u64);                // Value type: 64-bit unsigned int
} exec_count SEC(".maps");               // Place in .maps section

// This program will be attached to a perf event
SEC("perf_event")
int count_exec(struct bpf_perf_event_data *ctx) {
    __u32 key = 0;                       // We only use index 0
    __u64 *count;
    
    // Look up the counter in our map
    count = bpf_map_lookup_elem(&exec_count, &key);
    if (count) {
        // Atomically increment the counter
        __sync_fetch_and_add(count, 1);
    }
    
    return 0;
}

char LICENSE[] SEC("license") = "GPL";