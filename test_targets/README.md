# AFL++ Scheduler Test Target

This directory contains a test target and scripts for evaluating the AFL++ feedback-guided CPU scheduler.

## Contents

- `scheduler_test.c`: A test program with multiple paths and potential crashes
- `Makefile`: Compiles the test program with AFL++ instrumentation
- `input/`: Directory containing initial test cases
- `run_test.sh`: Script to run a quick test of the scheduler

## Test Target Description

The test target (`scheduler_test.c`) is designed to have:

1. Multiple execution paths based on input data
2. Several potential crash conditions
3. Varying execution times for different paths
4. Hard-to-reach code paths that require specific inputs

The program processes input data and has the following main paths:

- Path 1: Triggered by "FUZZ" magic bytes
  - Path 1.1: Deeper path requiring specific bytes after "FUZZ"
    - Contains a potential divide-by-zero crash

- Path 2: Triggered by "TEST" magic bytes
  - Multiple sub-paths based on integer values
  - Contains a potential buffer overflow

- Path 3: Triggered by "CRAS" magic bytes
  - Multiple crash types based on subsequent bytes
  - Contains null pointer dereference, out-of-bounds access, etc.

- Path 4: Default path for other inputs
  - Multiple sub-paths based on checksum of input

Each path has different processing times, simulated by the `slow_processing()` function, to create varying CPU demands.

## Running the Test

To run a quick test of the scheduler:

```bash
./run_test.sh
```

This will:
1. Compile the target
2. Start the eBPF scheduler
3. Run two fuzzing instances (one with scheduler feedback, one without)
4. Generate metrics visualizations
5. Compare the results

You can customize the test duration and output directories:

```bash
./run_test.sh -d 600 -o ./custom_output -m ./custom_metrics
```

Options:
- `-d DURATION`: Test duration in seconds (default: 300)
- `-o OUTPUT_DIR`: Directory for fuzzing output (default: ./output)
- `-m METRICS_DIR`: Directory for metrics (default: ./metrics)

## Interpreting Results

After the test completes, the script will print a summary comparing the performance of the scheduler-enabled instance versus the regular instance. It will show:

- Paths found by each instance
- Executions completed by each instance
- Percentage improvement or degradation

The metrics visualizations in `METRICS_DIR/plots` provide more detailed insights into the scheduler's performance.

## Manual Testing

You can also run manual tests with the target:

1. Compile the target:
   ```bash
   make
   ```

2. Run with a specific input file:
   ```bash
   ./scheduler_test input/test1.txt
   ```

3. Or provide input via stdin:
   ```bash
   echo "FUZZABCD" | ./scheduler_test
   ```
