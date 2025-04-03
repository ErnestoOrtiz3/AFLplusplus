// SPDX-License-Identifier: GPL-2.0
/*
 * AFL++ Feedback-Guided CPU Scheduler
 * ----------------------------------
 *
 * Copyright 2024 AFLplusplus Project. All rights reserved.
 *
 * This eBPF program implements a custom scheduler for the Linux kernel's
 * sched_ext framework that prioritizes AFL++ fuzzing processes based on
 * their performance metrics.
 */

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/sched.h>
#include <linux/sched_ext.h>

/* Structure that matches the user-space scheduler_feedback_t */
struct fuzzer_stats {
    __u64 last_update_time;     /* Timestamp of last update (ms) */
    __u32 new_edges_found;      /* New edges found since last update */
    __u32 total_edges_found;    /* Total edges found by this fuzzer */
    __u32 execs_per_sec;        /* Current execution speed */
    __u32 paths_found;          /* Total paths discovered */
    __u32 unique_crashes;       /* Number of unique crashes found */
    __u32 unique_hangs;         /* Number of unique hangs found */
    __u32 queue_cycle;          /* Current queue cycle */
    __u32 pending_favs;         /* Number of pending favored paths */
    __u8  performance_score;    /* Calculated performance score (0-100) */
    __u8  reserved[3];          /* Padding for alignment */
};

/* Map to store fuzzer performance metrics */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);         /* PID */
    __type(value, struct fuzzer_stats);
} fuzzer_performance SEC(".maps");

/* Map to store process scheduling weights */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);         /* PID */
    __type(value, __u32);       /* Weight */
} process_weights SEC(".maps");

/* Calculate weight based on fuzzer performance */
static __u32 calculate_weight(struct fuzzer_stats *stats)
{
    __u32 base_weight = 100;  // Base weight
    __u32 bonus = 0;
    
    // Boost for finding new edges
    if (stats->new_edges_found > 0) {
        bonus += stats->new_edges_found * 20;
    }
    
    // Boost for finding crashes
    if (stats->unique_crashes > 0) {
        bonus += 50;
    }
    
    // Boost for high execution speed
    if (stats->execs_per_sec > 500) {
        bonus += 10;
    }
    
    // Boost based on performance score
    bonus += stats->performance_score;
    
    // Apply time decay
    __u64 time_since_update = bpf_ktime_get_ns() / 1000000 - stats->last_update_time;
    if (time_since_update > 5000) {  // 5 seconds
        bonus = bonus / 2;  // Halve the bonus after 5 seconds
    }
    
    return base_weight + bonus;
}

/* sched_ext enqueue hook */
SEC("sched_ext/enqueue")
int afl_enqueue(struct task_struct *task, u64 enq_flags)
{
    __u32 pid = bpf_get_task_pid(task);
    struct fuzzer_stats *stats;
    __u32 weight = 100;  // Default weight
    
    // Check if this is an AFL++ fuzzer process
    stats = bpf_map_lookup_elem(&fuzzer_performance, &pid);
    if (stats) {
        // Calculate weight based on performance
        weight = calculate_weight(stats);
        
        // Store the weight for this process
        bpf_map_update_elem(&process_weights, &pid, &weight, BPF_ANY);
    }
    
    // Enqueue the task with the calculated weight
    bpf_sched_ext_enqueue(task, weight, 0);
    return 0;
}

/* sched_ext pick_next hook */
SEC("sched_ext/pick_next")
struct task_struct *afl_pick_next(struct sched_ext_pick_args *args)
{
    // Use the default pick_next implementation
    // The weights we set in enqueue will influence the selection
    return bpf_sched_ext_pick_next(args);
}

/* License (required for BPF programs) */
char LICENSE[] SEC("license") = "GPL";
