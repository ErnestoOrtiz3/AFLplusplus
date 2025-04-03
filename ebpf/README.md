# AFL++ Feedback-Guided CPU Scheduler

This component implements a custom CPU scheduler for AFL++ using the Linux kernel's `sched_ext` framework. The scheduler prioritizes fuzzing processes that are generating useful feedback (new coverage, crashes, etc.) by giving them more CPU time.

## Requirements

- Linux kernel 6.6+ with `CONFIG_SCHED_EXT=y`
- LLVM/Clang 14+
- libbpf development files

## Installation

1. Install the required dependencies:

```bash
# For Debian/Ubuntu
sudo apt-get install clang llvm libelf-dev libbpf-dev linux-headers-$(uname -r)

# For Fedora
sudo dnf install clang llvm elfutils-libelf-devel libbpf-devel kernel-devel
```

2. Build the scheduler components:

```bash
cd ebpf
make
```

## Usage

1. Enable scheduler feedback in AFL++:

```bash
afl-fuzz -i input -o output -S scheduler [other options] -- /path/to/target
```

2. Load the scheduler (requires root privileges):

```bash
# Default metrics directory (./scheduler_metrics)
sudo ./afl-scheduler-load.sh

# Or specify a custom metrics directory
sudo ./afl-scheduler-load.sh /path/to/metrics/dir
```

The scheduler daemon will automatically detect running AFL++ instances with scheduler feedback enabled and prioritize them based on their performance.

## How It Works

1. AFL++ processes with `-S scheduler` option enabled expose their performance metrics through shared memory.
2. The scheduler daemon reads these metrics and updates an eBPF map.
3. The eBPF scheduler uses these metrics to assign weights to fuzzing processes.
4. Processes that find new coverage or crashes get higher weights, resulting in more CPU time.

## Performance Metrics Used

- New edges found
- Total edges found
- Execution speed (execs/sec)
- Unique crashes found
- Queue cycle progress
- Performance score (calculated by AFL++)

## Performance Metrics Collection

The scheduler daemon includes a metrics collection system that tracks and analyzes the effectiveness of the scheduling decisions. This helps you evaluate whether the scheduler is improving fuzzing performance.

### Collected Metrics

- Edge coverage growth over time
- Crash discovery rate
- Correlation between prioritization and performance
- Scheduling weights assigned to each fuzzer
- Overall scheduler effectiveness

### Metrics Reports

The daemon generates several types of reports:

1. **Real-time summary**: Updated continuously in `summary.txt`
2. **Periodic reports**: Generated every 5 minutes in `report_*.txt`
3. **Final report**: Generated when the daemon exits

### Visualizing Metrics

A Python script is provided to visualize the collected metrics:

```bash
./plot_metrics.py /path/to/metrics/dir
```

This generates several plots:
- Edge coverage over time
- Edge discovery rate
- Weight vs. performance correlation
- Prioritization effectiveness
- Crash discovery rate
- Weight distribution

## Troubleshooting

- Make sure your kernel supports `sched_ext` (Linux 6.6+)
- Check if the `sched_ext` module is loaded: `lsmod | grep sched_ext`
- Run the daemon with `strace` to debug issues: `sudo strace -f ./afl_scheduler_daemon`
- For metrics visualization, install required Python packages: `pip install pandas matplotlib numpy`

## License

This component is licensed under the Apache License 2.0, the same as AFL++.
