# AFL++ CPU Scheduler

A custom eBPF CPU scheduler for AFL++ that dynamically prioritizes fuzzing processes based on their productivity. This scheduler detects which AFL++ instances are discovering new paths or crashes and gives them more CPU time, while reducing CPU allocation for less productive fuzzers.

## Features

- **Dynamic Priority Adjustment**: Automatically gives more CPU time to fuzzers that are finding new paths or crashes
- **Immediate Boosting**: Provides an immediate priority boost when a fuzzer finds something interesting
- **Minimal Overhead**: Uses efficient polling with optimization to minimize impact on fuzzing performance
- **Scalable**: Works with any number of AFL++ instances
- **No AFL++ Modifications**: Works with standard AFL++ without code changes

## Requirements

- Linux kernel with sched_ext support (5.16+ with the sched_ext patch or 6.6+ with built-in support)
- libbpf development files
- LLVM and Clang for BPF compilation
- bpftool

## Building

```bash
# Install dependencies (Ubuntu/Debian)
sudo apt-get install clang llvm libelf-dev libbpf-dev bpftool make gcc

# Clone the repository
git clone https://github.com/yourusername/afl-cpu-scheduler.git
cd afl-cpu-scheduler

# Build
make
```

## Usage

The scheduler consists of two components:

1. **Monitoring Daemon** (`afl_monitor`): Tracks AFL++ processes and their performance
2. **BPF Scheduler** (`afl_sched`): Implements the custom scheduling policy

### Step 1: Start the Monitoring Daemon

```bash
sudo ./afl_monitor [-i poll_interval_ms]
```

Options:
- `-i poll_interval_ms`: Polling interval in milliseconds (default: 1000, min: 100, max: 2000)

### Step 2: Load the BPF Scheduler

```bash
sudo ./afl_sched
```

### Step 3: Run Your AFL++ Instances

Run your AFL++ instances as you normally would. The scheduler will automatically detect them and adjust their priorities based on their performance.

```bash
# Example: Running multiple AFL++ instances
./afl-fuzz -i input -o output -S fuzzer1 ./target @@
./afl-fuzz -i input -o output -S fuzzer2 ./target @@
./afl-fuzz -i input -o output -S fuzzer3 ./target @@
```

## How It Works

1. The monitoring daemon periodically scans for AFL++ processes and tracks their output directories
2. When a fuzzer discovers a new path or crash, its score is increased
3. Scores decay over time to ensure that only recently productive fuzzers are prioritized
4. The BPF scheduler uses these scores to adjust the CPU time allocation for each fuzzer
5. Fuzzers that find new paths or crashes get an immediate priority boost

## Tuning

The scheduler has several parameters that can be adjusted:

- **Poll Interval**: How frequently the monitoring daemon checks for new paths/crashes
- **Weight Scale Factor**: The maximum priority multiplier for the best-performing fuzzer
- **Minimum Weight Percentage**: The minimum CPU allocation as a percentage of fair share
- **Score Decay Factor**: How quickly scores decay over time
- **Boost Duration**: How long a fuzzer gets boosted after finding something interesting

These parameters can be adjusted in the source code before building.

## Limitations

- Requires root privileges to load the BPF scheduler
- Only works on Linux systems with sched_ext support
- May not be optimal for all fuzzing workloads (some experimentation may be needed)

## License

This project is licensed under the MIT License - see the LICENSE file for details.
