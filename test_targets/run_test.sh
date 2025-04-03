#!/bin/bash
# Quick test script for the AFL++ scheduler

# Default settings
DURATION=300  # 5 minutes by default
OUTPUT_DIR="./output"
METRICS_DIR="./metrics"

# Parse command line arguments
while getopts "d:o:m:" opt; do
    case $opt in
        d) DURATION="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        m) METRICS_DIR="$OPTARG" ;;
        *) echo "Usage: $0 [-d DURATION] [-o OUTPUT_DIR] [-m METRICS_DIR]"; exit 1 ;;
    esac
done

# Create output directories
mkdir -p "$OUTPUT_DIR" "$METRICS_DIR"

# Compile the target
echo "Compiling target..."
make

if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

# Start the scheduler
echo "Starting scheduler..."
cd ../ebpf
sudo ./afl-scheduler-load.sh "$METRICS_DIR" &
SCHEDULER_PID=$!

# Give the scheduler time to initialize
sleep 2

# Start fuzzing
echo "Starting fuzzing with scheduler feedback..."
cd ../test_targets
AFL_SKIP_CPUFREQ=1 afl-fuzz -i input -o "$OUTPUT_DIR" -S scheduler -D -V "$DURATION" -- ./scheduler_test &
FUZZER1_PID=$!

# Start a second fuzzer without scheduler feedback
echo "Starting fuzzing without scheduler feedback..."
AFL_SKIP_CPUFREQ=1 afl-fuzz -i input -o "$OUTPUT_DIR" -S regular -D -V "$DURATION" -- ./scheduler_test &
FUZZER2_PID=$!

# Wait for fuzzing to complete
wait $FUZZER1_PID
wait $FUZZER2_PID

# Stop the scheduler
echo "Stopping scheduler..."
sudo kill $SCHEDULER_PID

# Generate metrics visualizations
echo "Generating metrics visualizations..."
cd ../ebpf
./plot_metrics.py "$METRICS_DIR" "$METRICS_DIR/plots"

# Print summary
echo "Test completed!"
echo "Results are available in $OUTPUT_DIR"
echo "Metrics are available in $METRICS_DIR"
echo "Visualizations are available in $METRICS_DIR/plots"

# Compare results
echo "Comparing results..."
SCHEDULER_PATHS=$(grep "paths_total" "$OUTPUT_DIR/scheduler/fuzzer_stats" | awk '{print $3}')
REGULAR_PATHS=$(grep "paths_total" "$OUTPUT_DIR/regular/fuzzer_stats" | awk '{print $3}')
SCHEDULER_EXECS=$(grep "execs_done" "$OUTPUT_DIR/scheduler/fuzzer_stats" | awk '{print $3}')
REGULAR_EXECS=$(grep "execs_done" "$OUTPUT_DIR/regular/fuzzer_stats" | awk '{print $3}')

echo "Scheduler feedback instance:"
echo "  Paths found: $SCHEDULER_PATHS"
echo "  Executions: $SCHEDULER_EXECS"
echo "Regular instance:"
echo "  Paths found: $REGULAR_PATHS"
echo "  Executions: $REGULAR_EXECS"

if [ "$SCHEDULER_PATHS" -gt "$REGULAR_PATHS" ]; then
    IMPROVEMENT=$(echo "scale=2; ($SCHEDULER_PATHS - $REGULAR_PATHS) * 100 / $REGULAR_PATHS" | bc)
    echo "The scheduler improved path discovery by $IMPROVEMENT%"
elif [ "$SCHEDULER_PATHS" -lt "$REGULAR_PATHS" ]; then
    DEGRADATION=$(echo "scale=2; ($REGULAR_PATHS - $SCHEDULER_PATHS) * 100 / $SCHEDULER_PATHS" | bc)
    echo "The scheduler degraded path discovery by $DEGRADATION%"
else
    echo "The scheduler had no effect on path discovery"
fi

if [ "$SCHEDULER_EXECS" -gt "$REGULAR_EXECS" ]; then
    IMPROVEMENT=$(echo "scale=2; ($SCHEDULER_EXECS - $REGULAR_EXECS) * 100 / $REGULAR_EXECS" | bc)
    echo "The scheduler improved execution speed by $IMPROVEMENT%"
elif [ "$SCHEDULER_EXECS" -lt "$REGULAR_EXECS" ]; then
    DEGRADATION=$(echo "scale=2; ($REGULAR_EXECS - $SCHEDULER_EXECS) * 100 / $SCHEDULER_EXECS" | bc)
    echo "The scheduler degraded execution speed by $DEGRADATION%"
else
    echo "The scheduler had no effect on execution speed"
fi
