# AFL++ Scheduler Feedback Test

This document describes how to test the AFL++ scheduler feedback mechanism without requiring the eBPF scheduler component.

## Overview

The scheduler feedback mechanism in AFL++ exposes performance metrics through shared memory, which can be used by external schedulers to prioritize fuzzing processes. This test script verifies that the feedback mechanism works correctly, even without the eBPF scheduler being available.

## Requirements

- AFL++ compiled with scheduler feedback support
- No need for kernel with sched_ext support
- Python 3 with pandas and matplotlib (for visualization)

## Running the Test

To run the test:

```bash
./run_feedback_test.sh
```

This will:
1. Compile the target
2. Start three fuzzing instances:
   - One main instance
   - One with scheduler feedback enabled
   - One regular secondary instance
3. Monitor the shared memory used by the scheduler feedback
4. Generate visualizations of the metrics

You can customize the test duration and output directories:

```bash
./run_feedback_test.sh -d 600 -o ./custom_output -m ./custom_metrics
```

Options:
- `-d DURATION`: Test duration in seconds (default: 300)
- `-o OUTPUT_DIR`: Directory for fuzzing output (default: ./output_feedback)
- `-m METRICS_DIR`: Directory for metrics (default: ./metrics_feedback)

## What This Test Verifies

This test verifies that:

1. The `-S scheduler` option correctly enables the scheduler feedback mechanism
2. AFL++ creates and populates the shared memory with performance metrics
3. The metrics are updated in real-time as the fuzzing progresses
4. External processes can access and read these metrics

## Monitoring Output

During the test, a simple monitoring program will:

1. Attach to the shared memory created by AFL++
2. Periodically read and display the performance metrics
3. Save the metrics to a CSV file for later analysis
4. Generate visualizations of the metrics over time

## Visualizations

After the test completes, several visualizations will be generated in the `METRICS_DIR/plots/` directory:

- `total_edges.png`: Total edges found over time
- `new_edges.png`: New edges found over time
- `execs_per_sec.png`: Executions per second over time
- `performance_score.png`: Performance score over time
- `paths.png`: Paths found over time

These visualizations help you understand how the fuzzing performance changes over time and verify that the metrics are being correctly tracked.

## Next Steps

Once you have verified that the scheduler feedback mechanism works correctly, you can:

1. Recompile your kernel with CONFIG_SCHED_EXT=y
2. Build the eBPF scheduler components
3. Run the full test with the eBPF scheduler using `./run_test.sh`
