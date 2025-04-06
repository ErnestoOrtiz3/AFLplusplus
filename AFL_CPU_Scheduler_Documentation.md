# AFL++ CPU Scheduler Documentation

This document provides a comprehensive overview of the AFL++ CPU Scheduler implementation, including all components, their interactions, and the execution flow from initialization to test comparison.

## Overview

The AFL++ CPU Scheduler is designed to improve fuzzing efficiency by prioritizing AFL++ instances that produce better feedback (finding more paths, crashes, etc.). It consists of several components:

1. **eBPF Scheduler**: A custom scheduler based on the Linux Sched_ext framework that assigns CPU resources based on process priorities.
2. **AFL++ Scheduler Feedback**: A mechanism in AFL++ that exposes performance metrics via shared memory.
3. **Priority Daemon**: A Python daemon that reads feedback from AFL++ instances and adjusts their priorities.
4. **Test Scripts**: Scripts to run and compare tests with and without scheduler feedback.
5. **Metrics Collection**: Scripts to collect and aggregate performance metrics.

## File Structure

### Core Components

1. **`/scx/`**: Directory containing the eBPF scheduler implementation (based on Sched_ext).
   - `scx_simple`: A simple eBPF scheduler that assigns CPU resources based on process priorities.

2. **`/afl_scheduler/`**: Directory containing the scheduler integration with AFL++.
   - `afl_priority_daemon.py`: Python daemon that reads feedback from AFL++ instances and adjusts their priorities.
   - `scheduler_feedback.h`: C header file defining the shared memory structure for scheduler feedback.

### Test Infrastructure

1. **`/test_targets/`**: Directory containing test scripts and targets.
   - `run_multi_feedback_test.sh`: Script to run multiple AFL++ instances with scheduler feedback enabled.
   - `collect_multi_metrics.sh`: Script to collect metrics from multiple AFL++ instances.
   - `compare_multi_tests.sh`: Script to run and compare tests with and without scheduler feedback.
   - `scheduler_test`: Simple test target for fuzzing.
   - `input/`: Directory containing initial test cases.

## Component Details

### 1. eBPF Scheduler (`scx_simple`)

The `scx_simple` scheduler is a custom eBPF scheduler based on the Linux Sched_ext framework. It assigns CPU resources based on process priorities, giving more CPU time to processes with higher priorities (lower nice values).

### 2. AFL++ Scheduler Feedback

AFL++ has been modified to expose performance metrics via shared memory. When an AFL++ instance is started with the `-S scheduler` flag, it initializes a shared memory segment and writes the shared memory ID to a file named `scheduler_feedback.txt` in its output directory.

The shared memory structure is defined in `scheduler_feedback.h` and includes the following metrics:
- Process ID
- Executions per second
- Paths found
- Unique crashes
- New edges found
- Performance score

### 3. Priority Daemon (`afl_priority_daemon.py`)

The priority daemon is a Python script that:
1. Scans for AFL++ instances with scheduler feedback enabled
2. Reads the shared memory ID from the `scheduler_feedback.txt` file
3. Attaches to the shared memory to read performance metrics
4. Calculates a priority (nice value) based on the metrics
5. Adjusts the process priority using the `renice` command
6. Logs metrics and priority adjustments

```python
class SchedulerFeedback(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_int),
        ("execs_per_sec", ctypes.c_float),
        ("paths_total", ctypes.c_int),
        ("unique_crashes", ctypes.c_int),
        ("new_edges_found", ctypes.c_int),
        ("performance_score", ctypes.c_float)
    ]
```

The daemon calculates process priorities based on:
- New edges found: Higher priority for instances finding new edges
- Unique crashes: Higher priority for instances finding crashes
- Execution speed: Higher priority for instances with high execution speed
- Performance score: Higher priority for instances with high performance score

### 4. Test Scripts

#### `run_multi_feedback_test.sh`

This script runs multiple AFL++ instances with or without scheduler feedback enabled:

1. **Initialization**:
   - Parses command-line arguments: duration, number of instances, output directory, etc.
   - Creates output directories
   - Compiles the target

2. **Scheduler Setup**:
   - If feedback is enabled, starts the `scx_simple` scheduler
   - Starts the AFL++ priority daemon

3. **Metrics Collection**:
   - Starts the metrics collection script in the background

4. **AFL++ Instances**:
   - Starts multiple AFL++ instances
   - If feedback is enabled, uses the naming scheme `scheduler0`, `scheduler1`, etc.
   - If feedback is disabled, uses the naming scheme `fuzzer0`, `fuzzer1`, etc.

5. **Cleanup**:
   - Waits for all instances to complete
   - Stops the scheduler and daemon
   - Generates a summary report

#### `collect_multi_metrics.sh`

This script collects metrics from multiple AFL++ instances:

1. **Initialization**:
   - Parses command-line arguments: interval, output directory, etc.
   - Creates metrics log files

2. **Metrics Collection**:
   - Periodically extracts metrics from each instance's `fuzzer_stats` file
   - Logs individual instance metrics
   - Calculates and logs aggregate metrics

3. **Metrics Logged**:
   - Executions per second
   - Total paths found
   - Unique crashes
   - Unique hangs
   - Bitmap coverage
   - Last find time
   - Process nice value
   - Pending favorites
   - Cycles done
   - Scheduler statistics

#### `compare_multi_tests.sh`

This script runs and compares tests with and without scheduler feedback:

1. **Test Execution**:
   - Runs a test with scheduler feedback enabled
   - Runs a test without scheduler feedback enabled

2. **Metrics Extraction**:
   - Extracts metrics from both test groups
   - Calculates aggregate metrics for each group

3. **Comparison Report**:
   - Generates a comparison report with metrics from both groups
   - Calculates improvement percentages
   - Generates comparison plots (if gnuplot is available)

## Execution Flow

### 1. Initialization

```
compare_multi_tests.sh
  |
  ├── run_multi_feedback_test.sh (with feedback)
  |     |
  |     ├── Start scx_simple scheduler
  |     ├── Start afl_priority_daemon.py
  |     ├── Start collect_multi_metrics.sh
  |     └── Start multiple AFL++ instances with -S scheduler0, scheduler1, etc.
  |
  └── run_multi_feedback_test.sh (without feedback)
        |
        ├── Start collect_multi_metrics.sh
        └── Start multiple AFL++ instances with -S fuzzer0, fuzzer1, etc.
```

### 2. Runtime Operation

```
AFL++ Instance (with -S scheduler)
  |
  ├── Initialize scheduler feedback shared memory
  ├── Write shared memory ID to scheduler_feedback.txt
  └── Update shared memory with performance metrics

afl_priority_daemon.py
  |
  ├── Scan for scheduler_feedback.txt files
  ├── Read shared memory ID from each file
  ├── Attach to shared memory to read metrics
  ├── Calculate process priority based on metrics
  └── Adjust process priority using renice

collect_multi_metrics.sh
  |
  ├── Extract metrics from fuzzer_stats files
  ├── Log individual instance metrics
  └── Calculate and log aggregate metrics
```

### 3. Test Completion and Comparison

```
compare_multi_tests.sh
  |
  ├── Wait for both tests to complete
  ├── Extract metrics from both test groups
  |     |
  |     ├── Extract individual instance metrics
  |     └── Calculate aggregate metrics
  |
  ├── Generate comparison report
  |     |
  |     ├── Log metrics from both groups
  |     └── Calculate improvement percentages
  |
  └── Generate comparison plots
```

## Metrics and Aggregation

### Individual Instance Metrics

Metrics collected from each AFL++ instance include:
- Executions per second
- Total paths found
- Unique crashes
- Unique hangs
- Bitmap coverage
- Last find time
- Process nice value
- Pending favorites
- Cycles done

### Aggregate Metrics

Aggregate metrics calculated across all instances in a test group include:
- Total executions
- Total paths found
- Total crashes found
- Total hangs found
- Average bitmap coverage
- Average executions per second

### Comparison Metrics

The comparison report includes:
- Aggregate metrics from both test groups
- Improvement percentages for:
  - Executions
  - Paths found
  - Crashes found
  - Bitmap coverage

## Conclusion

The AFL++ CPU Scheduler is designed to improve fuzzing efficiency by prioritizing better-performing instances. The test infrastructure allows for rigorous evaluation of the scheduler's effectiveness by comparing aggregate performance metrics with and without scheduler feedback.

Future improvements could include:
- Enhanced priority calculation algorithms
- More sophisticated resource allocation strategies
- Integration with other AFL++ features like power schedules
- Support for distributed fuzzing
