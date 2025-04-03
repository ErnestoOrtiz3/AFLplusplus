# AFL++ Scheduler Metrics Collection

This document describes the metrics collection system for the AFL++ feedback-guided CPU scheduler. This system helps you evaluate whether the scheduler is improving fuzzing performance.

## Overview

The metrics collection system tracks and analyzes the effectiveness of scheduling decisions made by the eBPF scheduler. It collects data on:

1. Edge coverage growth over time
2. Crash discovery rate
3. Correlation between prioritization and performance
4. Scheduling weights assigned to each fuzzer
5. Overall scheduler effectiveness

## Collected Metrics

For each fuzzer process, the following metrics are collected:

| Metric | Description |
|--------|-------------|
| Total edges | Total number of edges covered |
| New edges | New edges found since last update |
| Crashes | Number of unique crashes found |
| Execution speed | Executions per second |
| Weight | Scheduling weight assigned |
| Prioritization | Whether the fuzzer was prioritized |

## Metrics Reports

The daemon generates several types of reports:

### 1. Real-time Summary

A continuously updated summary file (`summary.txt`) that provides a quick overview of the current state of all fuzzing processes.

### 2. Periodic Reports

Every 5 minutes, the daemon generates a detailed report (`report_<timestamp>.txt`) that includes:

- Overall statistics (runtime, processes tracked, scheduling decisions)
- Per-fuzzer statistics (coverage, crashes, scheduling weights)
- Effectiveness analysis (correlation between prioritization and performance)

### 3. Final Report

When the daemon exits, it generates a final comprehensive report that includes all the data collected during the run.

## Visualizing Metrics

A Python script (`plot_metrics.py`) is provided to visualize the collected metrics:

```bash
./plot_metrics.py /path/to/metrics/dir [output_dir]
```

This generates several plots:

### Edge Coverage Over Time

![Edge Coverage](../ebpf/example_plots/edge_coverage.png)

This plot shows the total edge coverage for each fuzzer over time, allowing you to see which fuzzers are discovering new paths more quickly.

### Edge Discovery Rate

![Edge Discovery Rate](../ebpf/example_plots/edge_discovery_rate.png)

This plot shows the cumulative new edges discovered by each fuzzer over time, providing insight into the rate of discovery.

### Weight vs. Performance

![Weight vs Performance](../ebpf/example_plots/weight_vs_performance.png)

This scatter plot shows the relationship between assigned weights and edge discovery rate, helping you evaluate if higher weights correlate with better performance.

### Prioritization Effectiveness

![Prioritization Effectiveness](../ebpf/example_plots/prioritization_effectiveness.png)

This bar chart compares the edge discovery rate when a fuzzer is prioritized versus when it's not, directly measuring the effectiveness of the scheduling decisions.

### Crash Discovery Rate

![Crash Discovery](../ebpf/example_plots/crash_discovery.png)

This plot shows the cumulative crashes discovered by each fuzzer over time.

### Weight Distribution

![Weight Distribution](../ebpf/example_plots/weight_distribution.png)

This histogram shows the distribution of weights assigned to each fuzzer, giving insight into the scheduler's behavior.

## Comparing Performance

A comparison script (`compare_performance.sh`) is provided to help you evaluate the scheduler's effectiveness:

```bash
./compare_performance.sh -i INPUT_DIR -t TARGET_BINARY [-a "TARGET_ARGS"] [-d DURATION] [-c NUM_CORES] [-o OUTPUT_DIR]
```

This script:

1. Runs a baseline fuzzing campaign without the scheduler
2. Runs an identical campaign with the scheduler
3. Compares the results and generates a summary report

The summary report includes:
- Paths found improvement percentage
- Executions improvement percentage
- Crashes improvement percentage

## Interpreting the Results

The effectiveness of the scheduler is measured by several key metrics:

### 1. Effectiveness Ratio

The ratio of edge discovery rate when prioritized versus when not prioritized. A ratio greater than 1.0 indicates the scheduler is effective.

| Ratio | Interpretation |
|-------|---------------|
| > 1.5 | Highly effective |
| 1.0 - 1.5 | Effective |
| 0.5 - 1.0 | Somewhat effective |
| < 0.5 | Not effective |

### 2. Performance Improvement

The percentage improvement in paths found, executions completed, and crashes discovered compared to a baseline run without the scheduler.

### 3. Resource Utilization

The scheduler should result in more efficient CPU utilization, with less idle time and more productive work being done.

## Requirements for Visualization

To use the visualization script, you need:

- Python 3.6+
- pandas
- matplotlib
- numpy

Install these with:

```bash
pip install pandas matplotlib numpy
```

## Troubleshooting

- If no metrics are being collected, check if the scheduler daemon is running and has permission to access the shared memory.
- If visualization fails, check that you have the required Python packages installed.
- For more detailed debugging, run the daemon with verbose logging: `./afl_scheduler_daemon /path/to/metrics/dir -v`
