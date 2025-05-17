// SPDX-License-Identifier: GPL-2.0
/*
 * AFL++ CPU Scheduler - Enhanced BPF Component (Simplified Version)
 *
 * This is an enhanced version of the custom scheduler for AFL++ fuzzing processes.
 * It includes optimizations for better performance and more effective prioritization.
 *
 * It also includes a uretprobe on the save_if_interesting function to detect
 * new discoveries (paths, crashes) and send events to user-space via perf events.
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

/* Define shared DSQ ID for non-AFL processes */
#define NON_AFL_SHARED_DSQ 1

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

/* Discovery event structure */
struct discovery_event {
    __u32 pid;           // Process ID that made the discovery
    __u64 timestamp;     // Timestamp of the discovery
    __u8 discovery_type; // 0 = path, 1 = crash, 2 = timeout
    __u8 saved;          // Return value from save_if_interesting (1 if saved, 0 if not)
};

/* Perf event map for sending discovery events to user-space */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 1024);
} discovery_events SEC(".maps");

/* Helper functions */

/* Check if a process is a critical system process */
static bool is_critical_system_process(struct task_struct *p)
{
    char comm[16];
    u16 rt_priority;

    // Check for RT priority tasks
    if (bpf_probe_read_kernel(&rt_priority, sizeof(rt_priority), &p->rt_priority)) {
        return false;
    }

    // RT priority tasks are critical
    if (rt_priority > 0) {
        return true;
    }

    // Read process name
    if (bpf_probe_read_kernel(comm, sizeof(comm), &p->comm)) {
        return false;
    }

    // Check for kswapd
    if (comm[0] == 'k' && comm[1] == 's' && comm[2] == 'w' &&
        comm[3] == 'a' && comm[4] == 'p' && comm[5] == 'd') {
        return true;
    }

    // Check for systemd
    if (comm[0] == 's' && comm[1] == 'y' && comm[2] == 's' &&
        comm[3] == 't' && comm[4] == 'e' && comm[5] == 'm' &&
        comm[6] == 'd') {
        return true;
    }

    return false;
}

/* Check if a process is an AFL stats process (afl-fuzz main process) */
static bool is_afl_stats_process(struct task_struct *p)
{
    char comm[16];
    pid_t pid, tgid;

    // Read process name
    if (bpf_probe_read_kernel(comm, sizeof(comm), &p->comm)) {
        return false;
    }

    // Check if it's afl-fuzz
    if (comm[0] == 'a' && comm[1] == 'f' && comm[2] == 'l' &&
        comm[3] == '-' && comm[4] == 'f' && comm[5] == 'u' &&
        comm[6] == 'z' && comm[7] == 'z') {

        // Check if it's the main process (group leader)
        if (bpf_probe_read_kernel(&pid, sizeof(pid), &p->pid) ||
            bpf_probe_read_kernel(&tgid, sizeof(tgid), &p->tgid)) {
            return false;
        }

        // Main process has pid == tgid
        if (pid == tgid) {
            return true;
        }
    }

    return false;
}

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

    // We'll use SCX_DSQ_LOCAL for all processes instead of creating a shared DSQ
    // This avoids the need for the sleepable flag

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

    // Also update the task's scx.dsq_vtime field to ensure consistency
    p->scx.dsq_vtime = task_context->vruntime;

    // Increment consecutive runs counter for fairness
    task_context->consecutive_runs++;

    // Enhanced fairness mechanism:
    // If this task has been running for too many consecutive ticks,
    // reduce its time slice to allow other tasks to run
    if (task_context->consecutive_runs > 30) {
        // After 30 consecutive runs, force preemption by setting slice to 0
        // This prevents any single AFL process from monopolizing the CPU
        p->scx.slice = 0;
    } else if (task_context->consecutive_runs > 15) {
        // After 15 consecutive runs, gradually reduce the time slice
        // This creates a smooth transition rather than an abrupt preemption
        u64 reduction_factor = (task_context->consecutive_runs - 15) * 5;
        if (reduction_factor > 90) reduction_factor = 90;

        // Reduce the slice by up to 90%
        p->scx.slice = p->scx.slice * (100 - reduction_factor) / 100;

        // Ensure a minimum slice
        if (p->scx.slice < slice_us_min / 2) {
            p->scx.slice = slice_us_min / 2;
        }
    }

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

    // Check for critical system processes first (highest priority)
    if (is_critical_system_process(p)) {
        // Critical system processes go directly to local queue with preemption
        // to ensure system stability
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_us, SCX_ENQ_PREEMPT);
        return 0;
    }

    // Check for AFL stats processes (afl-fuzz main processes)
    if (is_afl_stats_process(p)) {
        // Give AFL stats processes high priority with preemption to ensure
        // stats collection works properly
        scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice_us * 2, SCX_ENQ_PREEMPT);
        return 0;
    }

    // Check if this is an AFL process (fast check first, then full check if needed)
    if (!is_afl_process_fast(p) || !(is_afl = is_afl_process(p))) {
        // Non-AFL processes go to the shared non-AFL queue
        // They will only run when local queues are empty
        scx_bpf_dsq_insert(p, NON_AFL_SHARED_DSQ, slice_us, 0);
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

            // For boosted tasks, artificially lower their vruntime to give higher priority
            task_context->vruntime -= 1000000;  // Subtract a fixed amount to boost priority

            // Boosted AFL processes go directly to local queue with preemption
            // This allows them to preempt currently running tasks
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, SCX_ENQ_PREEMPT);

            // Update statistics
            update_stats(1, 1, 1);

            return 0;
        } else if (boost_until && (*boost_until + boost_decay_period_us > now)) {
            // Task is in decay period - gradual reduction of boost
            u64 decay_progress = (now - *boost_until) * 100 / boost_decay_period_us;
            u64 boost_factor = 200 - decay_progress; // 200% to 100%
            slice = slice_us * boost_factor / 100;
            is_boosted = true;

            // Track boost time (including decay period)
            u64 boost_duration = boost_decay_period_us - (now - *boost_until);
            bpf_map_update_elem(&afl_total_boost_time, &pid, &boost_duration, BPF_ANY);

            // For tasks in decay period, adjust vruntime proportionally
            task_context->vruntime -= (1000000 * (100 - decay_progress) / 100);

            // Tasks in decay period also go directly to local queue with preemption
            // but with a lower slice based on decay progress
            scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, SCX_ENQ_PREEMPT);

            // Update statistics
            update_stats(1, 1, 1);

            return 0;
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

    // Regular AFL processes go directly to local queue without preemption
    scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL, slice, 0);

    // Update statistics
    update_stats(1, 1, 0);

    return 0;
}

s32 BPF_STRUCT_OPS(afl_sched_dispatch, s32 cpu, struct task_struct *prev)
{
    // Try to move non-AFL tasks from the shared queue to the local queue
    // This ensures non-AFL processes run when there are no AFL processes in the local queue
    if (scx_bpf_dsq_move_to_local(NON_AFL_SHARED_DSQ)) {
        return 0;  // Successfully moved non-AFL tasks
    }

    // Implement fairness mechanism for system processes
    // If the previous task was an AFL process and ran many times consecutively,
    // we might want to yield to system tasks occasionally
    if (prev && is_afl_process(prev)) {
        struct task_ctx *task_context = get_task_ctx(prev);

        if (task_context && task_context->consecutive_runs > 20) {
            // After 20 consecutive runs, force a yield to give system processes a chance
            // This prevents complete starvation of system processes
            return -ENOENT;  // Tell the kernel to pick another task
        }
    }

    // If no tasks were moved, let the kernel know
    return -ENOENT;
}

/* Attach to the return of save_if_interesting function */
SEC("uretprobe/save_if_interesting:function")
int trace_save_if_interesting_ret(struct pt_regs *ctx)
{
    struct discovery_event event = {};

    // Get the return value (1 if saved, 0 if not)
    u8 ret = PT_REGS_RC(ctx);

    // Get the current PID
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    event.pid = pid;

    // Get current timestamp (in nanoseconds)
    u64 now_ns = bpf_ktime_get_ns();
    event.timestamp = now_ns;

    // For now, we don't know the discovery type (will be determined in user-space)
    // We'll use the monitoring daemon to check if it's a path or crash
    event.discovery_type = 0;

    // Store the return value
    event.saved = ret;

    // Only process actual discoveries (when something was saved)
    if (event.saved) {
        // DIRECT BOOST: Update the boost map directly from BPF
        // Convert nanoseconds to microseconds for consistency with other time values
        u64 now_us = now_ns / 1000;

        // Calculate boost until timestamp
        u64 boost_until = now_us + prio_boost_duration_us;

        // Update the boost map directly
        bpf_map_update_elem(&afl_boost_until, &pid, &boost_until, BPF_ANY);

        // Send the event to user-space via perf event (for monitoring only)
        bpf_perf_event_output(ctx, &discovery_events, BPF_F_CURRENT_CPU,
                             &event, sizeof(event));
    }

    return 0;
}

SEC(".struct_ops.link")
struct sched_ext_ops afl_sched_ops = {
    .init = (void *)afl_sched_init,
    .exit = (void *)afl_sched_exit,
    .tick = (void *)afl_sched_tick,
    .enqueue = (void *)afl_sched_enqueue,
    .dispatch = (void *)afl_sched_dispatch,
    .name = "afl_sched",
    .flags = 0, /* No special flags needed */
};
