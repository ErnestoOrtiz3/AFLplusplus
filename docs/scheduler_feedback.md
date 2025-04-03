# AFL++ Feedback-Guided CPU Scheduler

This document describes the feedback-guided CPU scheduler feature in AFL++, which allows external eBPF schedulers to prioritize fuzzing processes based on their performance.

## Overview

The feedback-guided CPU scheduler is a feature that allows AFL++ to expose performance metrics to an external eBPF-based CPU scheduler. This scheduler can then prioritize fuzzing processes that are generating useful feedback (new coverage, crashes, etc.) by giving them more CPU time.

This feature consists of two main components:

1. **AFL++ Scheduler Feedback**: A mechanism in AFL++ that exposes performance metrics through shared memory.
2. **eBPF Scheduler**: A custom CPU scheduler that reads these metrics and adjusts CPU allocation accordingly.

## Requirements

- Linux kernel 6.6+ with `CONFIG_SCHED_EXT=y`
- LLVM/Clang 14+
- libbpf development files

## Usage

### 1. Enable Scheduler Feedback in AFL++

To enable scheduler feedback in AFL++, use the `-S scheduler` option:

```bash
afl-fuzz -i input -o output -S scheduler [other options] -- /path/to/target
```

This will make AFL++ expose its performance metrics through shared memory.

### 2. Build and Load the eBPF Scheduler

First, build the eBPF scheduler components:

```bash
cd ebpf
make
```

Then, load the scheduler (requires root privileges):

```bash
sudo ./afl-scheduler-load.sh
```

The scheduler daemon will automatically detect running AFL++ instances with scheduler feedback enabled and prioritize them based on their performance.

## How It Works

1. When AFL++ is started with `-S scheduler`, it creates a shared memory region to expose its performance metrics.
2. The scheduler daemon periodically scans for AFL++ processes with scheduler feedback enabled.
3. When it finds such a process, it reads the performance metrics from the shared memory and updates an eBPF map.
4. The eBPF scheduler uses these metrics to assign weights to fuzzing processes.
5. Processes that find new coverage or crashes get higher weights, resulting in more CPU time.

## Performance Metrics

The following performance metrics are exposed by AFL++:

- New edges found
- Total edges found
- Execution speed (execs/sec)
- Unique crashes found
- Unique hangs found
- Queue cycle progress
- Performance score (calculated by AFL++)

## Implementation Details

### Shared Memory Structure

The shared memory structure used for scheduler feedback is defined in `include/scheduler_feedback.h`:

```c
typedef struct scheduler_feedback {
  pid_t pid;                  /* Process ID of this fuzzer */
  u64   last_update_time;     /* Timestamp of last update (ms) */
  u32   new_edges_found;      /* New edges found since last update */
  u32   total_edges_found;    /* Total edges found by this fuzzer */
  u32   execs_per_sec;        /* Current execution speed */
  u32   paths_found;          /* Total paths discovered */
  u32   unique_crashes;       /* Number of unique crashes found */
  u32   unique_hangs;         /* Number of unique hangs found */
  u32   queue_cycle;          /* Current queue cycle */
  u32   pending_favs;         /* Number of pending favored paths */
  u8    performance_score;    /* Calculated performance score (0-100) */
} scheduler_feedback_t;
```

### eBPF Scheduler

The eBPF scheduler is implemented in `ebpf/afl_scheduler.bpf.c`. It uses the `sched_ext` framework to:

1. Read performance metrics from the eBPF map
2. Calculate scheduling weights based on these metrics
3. Assign higher weights to processes that are finding new coverage or crashes

## Troubleshooting

- Make sure your kernel supports `sched_ext` (Linux 6.6+)
- Check if the `sched_ext` module is loaded: `lsmod | grep sched_ext`
- Run the daemon with `strace` to debug issues: `sudo strace -f ./afl_scheduler_daemon`
- Check if the shared memory is created: `ls -l /dev/shm/`
- Look for the `scheduler_feedback.txt` file in the AFL++ output directory

## References

- [Linux Kernel sched_ext Documentation](https://docs.kernel.org/scheduler/sched-ext.html)
- [eBPF Documentation](https://ebpf.io/what-is-ebpf/)
- [AFL++ Documentation](https://github.com/AFLplusplus/AFLplusplus)
