// SPDX-License-Identifier: GPL-2.0
/*
 * AFL++ CPU Scheduler - BPF Component
 *
 * This is a custom scheduler for AFL++ fuzzing processes based on scx_bpfland.
 * It prioritizes fuzzing processes that are discovering new paths or crashes.
 */

/* Define this before including any headers to avoid duplicate definitions */
#define BPF_NO_KFUNC_PROTOTYPES

/* Include only SCX headers and avoid system headers that cause conflicts */
#include "scx/common.bpf.h"
#include "scx/compat.bpf.h"

/* Use BPF helpers directly */
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <errno.h>

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

/* Global dispatch queue - using a priority queue instead of a regular queue */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 4096);
    __type(key, u32);
    __type(value, struct task_struct *);
} dispatch_q SEC(".maps");

/* Queue management */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct {
        u32 head;
        u32 tail;
    });
} queue_state SEC(".maps");

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
    char comm[16];
    
    // Use bpf_probe_read_kernel to safely read the comm field
    if (bpf_probe_read_kernel(comm, sizeof(comm), &p->comm))
        return false;
    
    // Check if the process name matches afl-fuzz
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
    pid_t pid;
    
    // Check if this is an AFL++ process
    if (is_afl_process(p)) {
        // Read the PID safely
        if (bpf_probe_read_kernel(&pid, sizeof(pid), &p->pid))
            return 100; // Default weight if read fails
        
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
    
    if (!p)
        return NULL;
    
    // Don't use bpf_core_read_user here, as it's causing verifier issues
    // Instead, rely on the SCX framework's validation
    
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

/* Queue helper functions */
static bool queue_push(struct task_struct *task)
{
    u32 key = 0;
    struct {
        u32 head;
        u32 tail;
    } *state;
    
    state = bpf_map_lookup_elem(&queue_state, &key);
    if (!state)
        return false;
    
    u32 next_tail = (state->tail + 1) % 4096;
    if (next_tail == state->head)
        return false;  // Queue is full
    
    key = state->tail;
    if (bpf_map_update_elem(&dispatch_q, &key, &task, BPF_ANY))
        return false;
    
    state->tail = next_tail;
    return true;
}

static struct task_struct *queue_pop(void)
{
    u32 key = 0;
    struct {
        u32 head;
        u32 tail;
    } *state;
    
    state = bpf_map_lookup_elem(&queue_state, &key);
    if (!state)
        return NULL;
    
    if (state->head == state->tail)
        return NULL;  // Queue is empty
    
    key = state->head;
    struct task_struct **task_ptr = bpf_map_lookup_elem(&dispatch_q, &key);
    if (!task_ptr)
        return NULL;
    
    struct task_struct *task = *task_ptr;
    
    state->head = (state->head + 1) % 4096;
    return task;
}

/* Scheduler operations */
s32 BPF_STRUCT_OPS(afl_sched_init)
{
    u32 key = 0;
    u64 zero = 0;
    
    bpf_map_update_elem(&min_vruntime, &key, &zero, BPF_ANY);
    
    return 0;
}

s32 BPF_STRUCT_OPS(afl_sched_exit)
{
    // Nothing to do
    return 0;
}

s32 BPF_STRUCT_OPS(afl_sched_tick, struct task_struct *p)
{
    struct task_ctx *task_context;
    u64 now, delta, weight;
    
    // Validate task pointer
    if (!p) {
        return 0;
    }
    
    // Get task context
    task_context = bpf_task_storage_get(&task_ctx_storage, p, 0, 0);
    if (!task_context) {
        return 0;
    }
    
    // Get current time and calculate how long the task has been running
    now = scx_bpf_now();
    delta = now - task_context->enqueued_at;
    
    // Get task weight
    weight = task_context->weight;
    
    // Update vruntime based on how long it ran and its weight
    // Higher weight = slower vruntime accumulation = more CPU time
    task_context->vruntime += delta * 100 / weight;
    
    // Update task context
    task_context->enqueued_at = now;
    return 0;
}

s32 BPF_STRUCT_OPS(afl_sched_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct task_ctx *task_context;
    u64 min_vruntime_val, weight;
    u64 slice;
    bool is_afl, is_boosted = false;
    pid_t pid;
    
    // Validate task pointer
    if (!p) {
        return -EINVAL;
    }
    
    // Get or create task context
    task_context = get_task_ctx(p);
    if (!task_context) {
        // Create new task context
        struct task_ctx new_ctx = {};
        
        // Initialize with current min_vruntime
        new_ctx.vruntime = get_min_vruntime();
        
        // Set weight based on task priority
        weight = get_task_weight(p);
        new_ctx.weight = weight;
        
        // Set enqueued time
        new_ctx.enqueued_at = scx_bpf_now();
        
        // Store task context
        bpf_task_storage_get(&task_ctx_storage, p, &new_ctx, BPF_NOEXIST);
        
        // Try to get it again
        task_context = get_task_ctx(p);
        if (!task_context) {
            // Failed to create task context
            return -ENOMEM;
        }
    } else {
        // Update existing task context
        task_context->enqueued_at = scx_bpf_now();
    }
    
    // Check if this is an AFL process
    is_afl = is_afl_process(p);
    
    // Check if this task has a priority boost
    if (is_afl) {
        // Read the PID safely
        if (bpf_probe_read_kernel(&pid, sizeof(pid), &p->pid)) {
            // Default behavior if read fails
            slice = slice_us;
        } else {
            u64 *boost_until = bpf_map_lookup_elem(&afl_boost_until, &pid);
            u64 now = scx_bpf_now();
            
            if (boost_until && *boost_until > now) {
                // Task is boosted, give it a longer slice
                slice = slice_us * 2;
                is_boosted = true;
            } else {
                // Normal slice based on weight
                slice = slice_us * task_context->weight / 100;
                if (slice < slice_us_min) {
                    slice = slice_us_min;
                }
            }
        }
    } else {
        // Non-AFL process gets normal slice
        slice = slice_us;
    }
    
    // Update minimum vruntime
    min_vruntime_val = get_min_vruntime();
    if (task_context->vruntime < min_vruntime_val) {
        update_min_vruntime(task_context->vruntime);
    }
    
    // Directly insert the task into the dispatch queue
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
    
    // Update statistics
    update_stats(1, is_afl ? 1 : 0, is_boosted ? 1 : 0);
    
    return 0;
}

s32 BPF_STRUCT_OPS(afl_sched_dispatch, s32 cpu, struct task_struct *prev)
{
    // We don't need to do anything here since we're using SCX_DSQ_LOCAL
    // The SCX framework will handle dispatching tasks from the local queue
    return -ENOENT;
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
