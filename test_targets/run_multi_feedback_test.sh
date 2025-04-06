#!/bin/bash
# Test script for the AFL++ scheduler with multiple instances

# Default settings
DURATION=600  # 10 minutes by default
NUM_INSTANCES=4  # Number of AFL++ instances to run
OUTPUT_DIR="./output_multi"
METRICS_DIR="./metrics_multi"
FEEDBACK_ENABLED=1  # 1 = enable scheduler feedback, 0 = disable

# Parse command line arguments
while getopts "d:n:o:m:f:" opt; do
    case $opt in
        d) DURATION="$OPTARG" ;;
        n) NUM_INSTANCES="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        m) METRICS_DIR="$OPTARG" ;;
        f) FEEDBACK_ENABLED="$OPTARG" ;;
        *) echo "Usage: $0 [-d DURATION] [-n NUM_INSTANCES] [-o OUTPUT_DIR] [-m METRICS_DIR] [-f FEEDBACK_ENABLED]"; exit 1 ;;
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

# Save current directory
CURRENT_DIR=$(pwd)
AFL_ROOT=$(cd .. && pwd)

# Start the scheduler if feedback is enabled
if [ "$FEEDBACK_ENABLED" -eq 1 ]; then
    echo "Starting scheduler..."
    cd $AFL_ROOT/scx/build/scheds/c
    sudo ./scx_simple &
    SCHEDULER_PID=$!
    echo "Using scx_simple scheduler"

    # Give the scheduler time to initialize
    sleep 2

    # Start the AFL++ priority daemon
    echo "Starting AFL++ priority daemon..."
    cd $CURRENT_DIR
    sudo $AFL_ROOT/afl_scheduler/afl_priority_daemon.py "$METRICS_DIR" 1 &
    DAEMON_PID=$!
    echo "AFL++ priority daemon started with PID $DAEMON_PID"
fi

# Start metrics collection in the background
echo "Starting metrics collection..."
cd $CURRENT_DIR
./collect_multi_metrics.sh -i 5 -o "$METRICS_DIR" -f "$OUTPUT_DIR" -d "$DURATION" -n "$NUM_INSTANCES" &
METRICS_PID=$!

# Start multiple AFL++ instances
echo "Starting $NUM_INSTANCES AFL++ instances..."
PIDS=()

for i in $(seq 0 $(($NUM_INSTANCES-1))); do
    INSTANCE_NAME="fuzzer$i"

    # Set instance name based on feedback
    if [ "$FEEDBACK_ENABLED" -eq 1 ]; then
        # Instances with feedback use "scheduler" prefix
        INSTANCE_NAME="scheduler$i"
    else
        # Instances without feedback use "fuzzer" prefix
        INSTANCE_NAME="fuzzer$i"
    fi

    # Start the fuzzer instance
    echo "Starting instance $INSTANCE_NAME..."
    AFL_SKIP_CPUFREQ=1 $AFL_ROOT/afl-fuzz -i input -o "$OUTPUT_DIR" -S "$INSTANCE_NAME" -V "$DURATION" -- ./scheduler_test &
    PIDS+=($!)

    # Small delay to avoid overwhelming the system
    sleep 1
done

# Wait for all fuzzing instances to complete
echo "Waiting for all instances to complete..."
for pid in "${PIDS[@]}"; do
    wait $pid
done

# Wait for metrics collection to complete
wait $METRICS_PID

# Stop the scheduler and daemon if they were started
if [ "$FEEDBACK_ENABLED" -eq 1 ]; then
    echo "Stopping scheduler and daemon..."
    sudo kill $SCHEDULER_PID
    sudo kill $DAEMON_PID
fi

# Generate summary report
echo "Generating summary report..."
SUMMARY_FILE="$OUTPUT_DIR/summary.txt"

echo "AFL++ Multi-Instance Test Summary" > "$SUMMARY_FILE"
echo "=================================" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"
echo "Test configuration:" >> "$SUMMARY_FILE"
echo "  Duration: $DURATION seconds" >> "$SUMMARY_FILE"
echo "  Number of instances: $NUM_INSTANCES" >> "$SUMMARY_FILE"
echo "  Scheduler feedback: $([ "$FEEDBACK_ENABLED" -eq 1 ] && echo "Enabled" || echo "Disabled")" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

# Collect aggregate metrics
TOTAL_EXECS=0
TOTAL_PATHS=0
TOTAL_CRASHES=0
TOTAL_HANGS=0

for i in $(seq 0 $(($NUM_INSTANCES-1))); do
    INSTANCE_NAME="fuzzer$i"
    STATS_FILE="$OUTPUT_DIR/$INSTANCE_NAME/fuzzer_stats"

    if [ -f "$STATS_FILE" ]; then
        # Extract metrics
        EXECS=$(grep "execs_done" "$STATS_FILE" 2>/dev/null | awk '{print $3}')
        PATHS=$(grep "paths_total" "$STATS_FILE" 2>/dev/null | awk '{print $3}')
        CRASHES=$(grep "unique_crashes" "$STATS_FILE" 2>/dev/null | awk '{print $3}')
        HANGS=$(grep "unique_hangs" "$STATS_FILE" 2>/dev/null | awk '{print $3}')

        # Add to totals
        TOTAL_EXECS=$((TOTAL_EXECS + ${EXECS:-0}))
        TOTAL_PATHS=$((TOTAL_PATHS + ${PATHS:-0}))
        TOTAL_CRASHES=$((TOTAL_CRASHES + ${CRASHES:-0}))
        TOTAL_HANGS=$((TOTAL_HANGS + ${HANGS:-0}))

        # Log individual instance metrics
        echo "Instance $INSTANCE_NAME:" >> "$SUMMARY_FILE"
        echo "  Executions: ${EXECS:-0}" >> "$SUMMARY_FILE"
        echo "  Paths found: ${PATHS:-0}" >> "$SUMMARY_FILE"
        echo "  Crashes found: ${CRASHES:-0}" >> "$SUMMARY_FILE"
        echo "  Hangs found: ${HANGS:-0}" >> "$SUMMARY_FILE"
        echo "" >> "$SUMMARY_FILE"
    else
        echo "Warning: Stats file not found for instance $INSTANCE_NAME" >> "$SUMMARY_FILE"
    fi
done

# Log aggregate metrics
echo "Aggregate metrics:" >> "$SUMMARY_FILE"
echo "  Total executions: $TOTAL_EXECS" >> "$SUMMARY_FILE"
echo "  Total paths found: $TOTAL_PATHS" >> "$SUMMARY_FILE"
echo "  Total crashes found: $TOTAL_CRASHES" >> "$SUMMARY_FILE"
echo "  Total hangs found: $TOTAL_HANGS" >> "$SUMMARY_FILE"
echo "" >> "$SUMMARY_FILE"

echo "Test completed!"
echo "Results are available in $OUTPUT_DIR"
echo "Metrics are available in $METRICS_DIR"
echo "Summary report: $SUMMARY_FILE"
