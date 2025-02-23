// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// Required GPL license for eBPF programs
char LICENSE[] SEC("license") = "GPL";


/* Format of sys_enter_execve tracepoint */
struct syscalls_enter_execve_args {
    __u64 unused;
    __u32 __syscall_nr;
    const char *filename;
    const char *const *argv;
    const char *const *envp;
};

// Define BPF map to store execution count
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);    // Array type map
    __uint(max_entries, 1);              // Single element array
    __type(key, __u32);                  // Key type: 32-bit unsigned int
    __type(value, __u64);                // Value type: 64-bit unsigned int
} exec_count SEC(".maps");               // Place in .maps section

// Attach to execve syscall entry point
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve_enter(struct syscalls_enter_execve_args *ctx)  {
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