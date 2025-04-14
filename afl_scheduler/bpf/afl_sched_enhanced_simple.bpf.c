// SPDX-License-Identifier: GPL-2.0
/*
 * AFL++ CPU Scheduler - Enhanced BPF Component (Simplified Version)
 *
 * This is an enhanced version of the custom scheduler for AFL++ fuzzing processes.
 * It includes optimizations for better performance and more effective prioritization.
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
const volatile u32 boost_weight = 1000;              // Weight to assign during boost period
const volatile u64 boost_decay_period_us = 2000000;  // Period over which boost decays after expiration

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
    u64 last_slice;       // Last time slice assigned
    u32 consecutive_runs; // Track consecutive runs for fairness
};

struct {
    __uint(type, BPF_MAP_TYPE_TASK_STORAGE);
    __uint(map_flags, BPF_F_NO_PREALLOC);
    __type(key, int);
    __type(value, struct task_ctx);
} task_ctx_storage SEC(".maps");

/* Global dispatch queue */
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

/* Statistics for boost time tracking */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, pid_t);
    __type(value, u64);
} afl_total_boost_time SEC(".maps");

/* Helper functions */

/* Fast check for AFL process - optimized version */
static bool is_afl_process_fast(struct task_struct *p)
{
    char first_char;
    
    // Just check the first character of comm to quickly filter out non-AFL processes
    if (bpf_probe_read_kernel(&first_char, sizeof(first_char), &p->comm[0]))
        return false;
    
    return first_char == 'a';
}

/* Full check for AFL process - more thorough but slower */
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

/* Get task weight with enhanced logic */
static u64 get_task_weight(struct task_struct *p)
{
    u32 *weight;
    u64 *boost_until;
    u64 now = scx_bpf_now();
    pid_t pid;
    u64 effective_weight = 100; // Default weight
    
    // Check if this is an AFL++ process
    if (is_afl_process(p)) {
        // Read the PID safely
        if (bpf_probe_read_kernel(&pid, sizeof(pid), &p->pid))
            return effective_weight; // Default weight if read fails
        
        // Check if this task has a priority boost
        boost_until = bpf_map_lookup_elem(&afl_boost_until, &pid);
        if (boost_until) {
            if (*boost_until > now) {
                // Task is fully boosted
                return boost_weight;
            } else if (*boost_until + boost_decay_period_us > now) {
                // Task is in the decay period - gradual decay from boost_weight to normal weight
                u64 decay_progress = (now - *boost_until) * 100 / boost_decay_period_us;
                
                // Get the base weight for this task
                weight = bpf_map_lookup_elem(&afl_weights, &pid);
                u64 base_weight = weight ? *weight : 100;
                
                // Calculate decaying weight: boost_weight -> base_weight
                u64 weight_diff = boost_weight > base_weight ? boost_weight - base_weight : 0;
                effective_weight = boost_weight - (weight_diff * decay_progress / 100);
                
                // Track boost time (including decay period)
                u64 boost_duration = boost_decay_period_us - (now - *boost_until);
                bpf_map_update_elem(&afl_total_boost_time, &pid, &boost_duration, BPF_ANY);
                
                return effective_weight;
            }
        }
        
        // Check if this task has a custom weight
        weight = bpf_map_lookup_elem(&afl_weights, &pid);
        if (weight) {
            effective_weight = *weight;
            
            // Apply simple scaling for high-weight tasks
            if (effective_weight > 100) {
                // Add 50% more weight to make high-weight tasks even more prioritized
                effective_weight = effective_weight * 3 / 2;
            }
            
            return effective_weight;
        }
    }
    
    return effective_weight;
}

static struct task_ctx *get_task_ctx(struct task_struct *p)
{
    struct task_ctx *ctx;
    
    if (!p)
        return NULL;
    
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
    
    // Fast path for non-AFL processes
    if (!is_afl_process_fast(p)) {
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
    
    // Increment consecutive runs counter for fairness
    task_context->consecutive_runs++;
    
    // Update task context
    task_context->enqueued_at = now;
    return 0;
}

s32 BPF_STRUCT_OPS(afl_sched_enqueue, struct task_struct *p, u64 enq_flags)
{
    struct task_ctx *task_context;
    u64 min_vruntime_val, weight;
    u64 slice;
    bool is_afl = false, is_boosted = false;
    pid_t pid;
    
    // Validate task pointer
    if (!p) {
        return -EINVAL;
    }
    
    // Fast path for non-AFL processes
    if (!is_afl_process_fast(p)) {
        // Use default slice for non-AFL processes
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_us, 0);
        return 0;
    }
    
    // Confirm this is an AFL process with full check
    is_afl = is_afl_process(p);
    if (!is_afl) {
        // Use default slice for non-AFL processes
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_us, 0);
        return 0;
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
        new_ctx.last_slice = slice_us;
        new_ctx.consecutive_runs = 0;
        
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
        
        // Reset consecutive runs counter if this is a new enqueue (not a preemption)
        if (!(enq_flags & SCX_ENQ_PREEMPT)) {
            task_context->consecutive_runs = 0;
        }
        
        // Update weight based on current priority
        weight = get_task_weight(p);
        task_context->weight = weight;
    }
    
    // Determine time slice based on weight and boost status
    if (bpf_probe_read_kernel(&pid, sizeof(pid), &p->pid)) {
        // Default behavior if read fails
        slice = slice_us;
    } else {
        u64 *boost_until = bpf_map_lookup_elem(&afl_boost_until, &pid);
        u64 now = scx_bpf_now();
        
        if (boost_until && *boost_until > now) {
            // Task is fully boosted
            slice = slice_us * 2;
            is_boosted = true;
            
            // Track boost time
            u64 boost_duration = *boost_until - now;
            bpf_map_update_elem(&afl_total_boost_time, &pid, &boost_duration, BPF_ANY);
        } else if (boost_until && (*boost_until + boost_decay_period_us > now)) {
            // Task is in decay period - gradual reduction of boost
            u64 decay_progress = (now - *boost_until) * 100 / boost_decay_period_us;
            u64 boost_factor = 200 - decay_progress; // 200% to 100%
            slice = slice_us * boost_factor / 100;
            is_boosted = true;
            
            // Track boost time (including decay period)
            u64 boost_duration = boost_decay_period_us - (now - *boost_until);
            bpf_map_update_elem(&afl_total_boost_time, &pid, &boost_duration, BPF_ANY);
        } else {
            // Normal slice based on weight
            u32 *weight_ptr = bpf_map_lookup_elem(&afl_weights, &pid);
            weight = weight_ptr ? *weight_ptr : 100;
            
            // Apply fairness adjustment for tasks that have run many times consecutively
            if (task_context->consecutive_runs > 10) {
                // Gradually reduce weight for tasks that have run too many times
                weight = weight * 90 / 100;
            }
            
            // Calculate slice based on weight
            slice = slice_us * weight / 100;
            
            // Ensure minimum slice
            if (slice < slice_us_min) {
                slice = slice_us_min;
            }
        }
    }
    
    // Store the assigned slice
    task_context->last_slice = slice;
    
    // Update minimum vruntime
    min_vruntime_val = get_min_vruntime();
    if (task_context->vruntime < min_vruntime_val) {
        update_min_vruntime(task_context->vruntime);
    }
    
    // Insert task into dispatch queue
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);
    
    // Update statistics
    update_stats(1, 1, is_boosted ? 1 : 0);
    
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
