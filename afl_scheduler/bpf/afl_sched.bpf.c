// SPDX-License-Identifier: GPL-2.0
/*
 * AFL++ CPU Scheduler - BPF Component
 *
 * This is a custom scheduler for AFL++ fuzzing processes based on scx_bpfland.
 * It prioritizes fuzzing processes that are discovering new paths or crashes.
 */

#include <linux/sched.h>
#include <linux/types.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <asm/current.h>
#include "scx/common.bpf.h"
#include "scx/compat.bpf.h"

char LICENSE[] SEC("license") = "GPL";

/* Scheduler configuration */
const volatile bool partial = false;
const volatile bool verbose = false;
const volatile u64 slice_us = 20000;
const volatile u64 slice_us_min = 5000;
const volatile u64 prio_boost_duration_us = 1000000; // 1 second boost after finding something

/* Shared memory key for communication with userspace */
const volatile u32 shm_key = 0x41464C53; // "AFLS"

/* Scheduler state */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} min_vruntime SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u32);
} afl_weights SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u64);
} afl_boost_until SEC(".maps");

/* Task context */
struct task_ctx {
    u64 vruntime;
    u64 weight;
    u64 enqueued_at;
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx_storage SEC(".maps");

/* Global dispatch queue */
struct {
    __uint(type, BPF_MAP_TYPE_QUEUE);
    __uint(max_entries, 4096);
    __type(value, struct task_struct *);
} dispatch_q SEC(".maps");

/* Statistics */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct {
        u64 dispatches;
        u64 afl_dispatches;
        u64 boosted_dispatches;
    });
} stats SEC(".maps");

/* Helper functions */
static bool is_afl_process(struct task_struct *p)
{
    const char *comm = BPF_CORE_READ(p, comm);
    
    // Check if the process name matches afl-fuzz
    // Note: comm is limited to 16 chars, so we can only check for "afl-fuzz"
    if (comm[0] == 'a' && comm[1] == 'f' && comm[2] == 'l' && 
        comm[3] == '-' && comm[4] == 'f' && comm[5] == 'u' && 
        comm[6] == 'z' && comm[7] == 'z') {
        return true;
    }
    
    return false;
}

static u64 get_task_weight(struct task_struct *p)
{
    u32 key = 0;
    u32 *weight;
    u64 *boost_until;
    u64 now = scx_bpf_now();
    
    // Check if this is an AFL++ process
    if (is_afl_process(p)) {
        pid_t pid = BPF_CORE_READ(p, pid);
        
        // Check if this task has a priority boost
        boost_until = bpf_map_lookup_elem(&afl_boost_until, &pid);
        if (boost_until && *boost_until > now) {
            // Task is boosted, give it maximum priority
            return 1000;
        }
        
        // Check if this task has a custom weight
        weight = bpf_map_lookup_elem(&afl_weights, &pid);
        if (weight) {
            return (u64)*weight;
        }
    }
    
    // Default weight for non-AFL processes or AFL processes without custom weight
    return 100;
}

static struct task_ctx *get_task_ctx(struct task_struct *p)
{
    struct task_ctx *ctx;
    
    ctx = bpf_task_storage_get(&task_ctx_storage, p, 0, 0);
    if (!ctx) {
        return NULL;
    }
    
    return ctx;
}

static u64 get_min_vruntime(void)
{
    u32 key = 0;
    u64 *min_vruntime_p;
    
    min_vruntime_p = bpf_map_lookup_elem(&min_vruntime, &key);
    if (!min_vruntime_p) {
        return 0;
    }
    
    return *min_vruntime_p;
}

static void update_min_vruntime(u64 vruntime)
{
    u32 key = 0;
    
    bpf_map_update_elem(&min_vruntime, &key, &vruntime, BPF_ANY);
}

static void update_stats(u64 dispatches, u64 afl_dispatches, u64 boosted_dispatches)
{
    u32 key = 0;
    struct {
        u64 dispatches;
        u64 afl_dispatches;
        u64 boosted_dispatches;
    } *stats_p;
    
    stats_p = bpf_map_lookup_elem(&stats, &key);
    if (!stats_p) {
        return;
    }
    
    stats_p->dispatches += dispatches;
    stats_p->afl_dispatches += afl_dispatches;
    stats_p->boosted_dispatches += boosted_dispatches;
}

/* Scheduler operations */
void BPF_STRUCT_OPS(afl_sched_init)
{
    u32 key = 0;
    u64 zero = 0;
    
    bpf_map_update_elem(&min_vruntime, &key, &zero, BPF_ANY);
}

void BPF_STRUCT_OPS(afl_sched_exit)
{
    // Nothing to do
}

void BPF_STRUCT_OPS(afl_sched_tick, struct task_struct *p)
{
    struct task_ctx *ctx;
    u64 now, delta, weight;
    
    ctx = get_task_ctx(p);
    if (!ctx) {
        return;
    }
    
    // Get current time and calculate how long the task has been running
    now = scx_bpf_now();
    delta = now - ctx->enqueued_at;
    
    // Get task weight
    weight = ctx->weight;
    
    // Update vruntime based on how long it ran and its weight
    // Higher weight = slower vruntime accumulation = more CPU time
    ctx->vruntime += delta * 100 / weight;
    
    // Update task context
    ctx->enqueued_at = now;
}

void BPF_STRUCT_OPS(afl_sched_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct task_ctx *ctx;
    u64 min_vruntime_val, weight;
    
    // Get or create task context
    ctx = bpf_task_storage_get(&task_ctx_storage, p, 0, BPF_LOCAL_STORAGE_GET_F_CREATE);
    if (!ctx) {
        // Failed to get task context, use default scheduling
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, SCX_SLICE_DFL, enq_flags);
        return;
    }
    
    // Get current minimum vruntime
    min_vruntime_val = get_min_vruntime();
    
    // Get task weight
    weight = get_task_weight(p);
    
    // Initialize task context if this is the first time we're seeing this task
    if (ctx->vruntime == 0) {
        ctx->vruntime = min_vruntime_val;
    } else if (ctx->vruntime < min_vruntime_val) {
        // Ensure vruntime doesn't fall too far behind
        ctx->vruntime = min_vruntime_val;
    }
    
    // Update task context
    ctx->weight = weight;
    ctx->enqueued_at = scx_bpf_now();
    
    // Insert task into dispatch queue
    bpf_map_push_elem(&dispatch_q, &p, 0);
}

void BPF_STRUCT_OPS(afl_sched_dispatch, s32 cpu, struct task_struct *prev)
{
    struct task_struct *next;
    struct task_ctx *ctx;
    u64 slice, min_vruntime_val;
    bool is_afl, is_boosted = false;
    
    // Try to get a task from the dispatch queue
    if (bpf_map_pop_elem(&dispatch_q, &next)) {
        // No tasks in queue
        return;
    }
    
    // Get task context
    ctx = get_task_ctx(next);
    if (!ctx) {
        // Failed to get task context, use default slice
        scx_bpf_dsq_insert(next, SCX_DSQ_LOCAL, SCX_SLICE_DFL, 0);
        return;
    }
    
    // Check if this is an AFL process
    is_afl = is_afl_process(next);
    
    // Check if this task has a priority boost
    if (is_afl) {
        pid_t pid = BPF_CORE_READ(next, pid);
        u64 *boost_until = bpf_map_lookup_elem(&afl_boost_until, &pid);
        u64 now = scx_bpf_now();
        
        if (boost_until && *boost_until > now) {
            // Task is boosted, give it a longer slice
            slice = slice_us * 2;
            is_boosted = true;
        } else {
            // Normal slice based on weight
            slice = slice_us * ctx->weight / 100;
            if (slice < slice_us_min) {
                slice = slice_us_min;
            }
        }
    } else {
        // Non-AFL process gets normal slice
        slice = slice_us;
    }
    
    // Update minimum vruntime
    min_vruntime_val = get_min_vruntime();
    if (ctx->vruntime < min_vruntime_val) {
        update_min_vruntime(ctx->vruntime);
    }
    
    // Dispatch task
    scx_bpf_dsq_insert(next, SCX_DSQ_LOCAL, slice, 0);
    
    // Update statistics
    update_stats(1, is_afl ? 1 : 0, is_boosted ? 1 : 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops afl_sched_ops = {
    .init = (void *)afl_sched_init,
    .exit = (void *)afl_sched_exit,
    .tick = (void *)afl_sched_tick,
    .enqueue = (void *)afl_sched_enqueue,
    .dispatch = (void *)afl_sched_dispatch,
    .name = "afl_sched",
};
