# AFL++ Feedback-Guided CPU Scheduler

This component implements a custom CPU scheduler for AFL++ using the Linux kernel's `sched_ext` framework. The scheduler prioritizes fuzzing processes that are generating useful feedback (new coverage, crashes, etc.) by giving them more CPU time.

## Requirements

- Linux kernel 6.6+ with `CONFIG_SCHED_EXT=y`
- LLVM/Clang 14+
- libbpf development files
- bpftool

## Installation

1. Install the required dependencies:

```bash
# For Debian/Ubuntu
sudo apt-get install clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r) bpftool

# For Fedora
sudo dnf install clang llvm elfutils-libelf-devel libbpf-devel kernel-devel bpftool
```

2. Build the scheduler components:

```bash
cd afl_scheduler
make
```

## Usage

1. Enable scheduler feedback in AFL++:

```bash
afl-fuzz -i input -o output -S scheduler [other options] -- /path/to/target
```

2. Load the scheduler (requires root privileges):

```bash
cd afl_scheduler
sudo ./afl-scheduler-load.sh
```

The scheduler will automatically detect running AFL++ instances with scheduler feedback enabled and prioritize them based on their performance.

## How It Works

1. When AFL++ is started with `-S scheduler`, it creates a shared memory region to expose its performance metrics.
2. The scheduler daemon periodically scans for AFL++ processes with scheduler feedback enabled.
3. When it finds such a process, it reads the performance metrics from the shared memory and updates a BPF map.
4. The BPF scheduler uses these metrics to assign weights to fuzzing processes.
5. Processes that find new coverage or crashes get higher weights, resulting in more CPU time.

## Performance Metrics

The following performance metrics are used to calculate process weights:

- New edges found
- Total edges found
- Execution speed (execs/sec)
- Unique crashes found
- Unique hangs found
- Performance score (calculated by AFL++)

## Testing

To test the scheduler, you can use the provided test scripts:

```bash
# Test with the AFL++ scheduler
cd test_targets
./run_scx_test.sh

# Compare different schedulers
./compare_schedulers.sh
```

## Troubleshooting

- Make sure your kernel supports `sched_ext` (Linux 6.6+)
- Check if the `sched_ext` module is loaded: `lsmod | grep sched_ext`
- Run the scheduler with strace to debug issues: `sudo strace -f ./afl_scheduler`
- Check if the shared memory is created: `ls -l /dev/shm/`
- Look for the `scheduler_feedback.txt` file in the AFL++ output directory
