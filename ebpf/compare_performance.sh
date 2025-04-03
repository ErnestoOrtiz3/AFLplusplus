#!/bin/bash
# AFL++ Scheduler Performance Comparison Script
#
# This script runs two identical fuzzing campaigns, one with the scheduler
# and one without, and compares the results.

# Default settings
DURATION=3600  # 1 hour by default
INPUT_DIR=""
TARGET_BINARY=""
TARGET_ARGS=""
NUM_CORES=3
OUTPUT_DIR="./comparison_results"

# Parse command line arguments
function show_usage {
    echo "Usage: $0 -i INPUT_DIR -t TARGET_BINARY [-a \"TARGET_ARGS\"] [-d DURATION] [-c NUM_CORES] [-o OUTPUT_DIR]"
    echo ""
    echo "Options:"
    echo "  -i INPUT_DIR      Directory containing initial test cases"
    echo "  -t TARGET_BINARY  Path to the target binary to fuzz"
    echo "  -a TARGET_ARGS    Arguments to pass to the target binary (in quotes)"
    echo "  -d DURATION       Duration of each test in seconds (default: 3600)"
    echo "  -c NUM_CORES      Number of cores to use for each test (default: 3)"
    echo "  -o OUTPUT_DIR     Directory to store results (default: ./comparison_results)"
    echo "  -h                Show this help message"
    exit 1
}

while getopts "i:t:a:d:c:o:h" opt; do
    case $opt in
        i) INPUT_DIR="$OPTARG" ;;
        t) TARGET_BINARY="$OPTARG" ;;
        a) TARGET_ARGS="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        c) NUM_CORES="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        h) show_usage ;;
        *) show_usage ;;
    esac
done

# Check required arguments
if [ -z "$INPUT_DIR" ] || [ -z "$TARGET_BINARY" ]; then
    echo "Error: Input directory and target binary are required."
    show_usage
fi

# Check if input directory exists
if [ ! -d "$INPUT_DIR" ]; then
    echo "Error: Input directory $INPUT_DIR does not exist."
    exit 1
fi

# Check if target binary exists
if [ ! -f "$TARGET_BINARY" ]; then
    echo "Error: Target binary $TARGET_BINARY does not exist."
    exit 1
fi

# Create output directories
BASELINE_DIR="$OUTPUT_DIR/baseline"
SCHEDULER_DIR="$OUTPUT_DIR/scheduler"
METRICS_DIR="$OUTPUT_DIR/metrics"

mkdir -p "$BASELINE_DIR" "$SCHEDULER_DIR" "$METRICS_DIR"

# Function to run a fuzzing campaign
function run_campaign {
    local name=$1
    local output_dir=$2
    local use_scheduler=$3
    local duration=$4
    
    echo "Starting $name campaign..."
    
    # Start main instance
    AFL_SKIP_CPUFREQ=1 afl-fuzz -i "$INPUT_DIR" -o "$output_dir" -M main -D -V $duration \
        -- "$TARGET_BINARY" $TARGET_ARGS &
    
    # Start secondary instances
    for i in $(seq 1 $((NUM_CORES-1))); do
        if [ $use_scheduler -eq 1 ] && [ $i -eq 1 ]; then
            # Use scheduler for the first secondary instance
            AFL_SKIP_CPUFREQ=1 afl-fuzz -i "$INPUT_DIR" -o "$output_dir" -S scheduler -D -V $duration \
                -- "$TARGET_BINARY" $TARGET_ARGS &
        else
            # Regular secondary instances
            AFL_SKIP_CPUFREQ=1 afl-fuzz -i "$INPUT_DIR" -o "$output_dir" -S "slave$i" -D -V $duration \
                -- "$TARGET_BINARY" $TARGET_ARGS &
        fi
    done
    
    # Wait for all instances to finish
    wait
    
    echo "$name campaign completed."
}

# Run baseline campaign (without scheduler)
echo "=== Running baseline campaign (without scheduler) ==="
run_campaign "Baseline" "$BASELINE_DIR" 0 "$DURATION"

# Run scheduler campaign
echo "=== Running campaign with scheduler ==="
echo "Loading scheduler..."
sudo ./afl-scheduler-load.sh "$METRICS_DIR" &
SCHEDULER_PID=$!

# Give the scheduler time to initialize
sleep 5

run_campaign "Scheduler" "$SCHEDULER_DIR" 1 "$DURATION"

# Stop the scheduler
echo "Stopping scheduler..."
sudo kill $SCHEDULER_PID

# Generate comparison report
echo "=== Generating comparison report ==="

# Create report directory
REPORT_DIR="$OUTPUT_DIR/report"
mkdir -p "$REPORT_DIR"

# Generate plots for baseline
echo "Generating baseline plots..."
afl-plot "$BASELINE_DIR" "$REPORT_DIR/baseline"

# Generate plots for scheduler
echo "Generating scheduler plots..."
afl-plot "$SCHEDULER_DIR" "$REPORT_DIR/scheduler"

# Generate metrics visualizations
echo "Generating metrics visualizations..."
./plot_metrics.py "$METRICS_DIR" "$REPORT_DIR/metrics"

# Generate summary report
echo "Generating summary report..."
cat > "$REPORT_DIR/summary.txt" << EOF
AFL++ Scheduler Performance Comparison
=====================================

Test duration: $DURATION seconds
Number of cores: $NUM_CORES
Target binary: $TARGET_BINARY
Target arguments: $TARGET_ARGS

Baseline Results:
----------------
EOF

# Add baseline statistics
BASELINE_STATS=$(grep -A 10 "total paths" "$BASELINE_DIR/main/fuzzer_stats")
echo "$BASELINE_STATS" >> "$REPORT_DIR/summary.txt"

echo -e "\nScheduler Results:\n----------------" >> "$REPORT_DIR/summary.txt"

# Add scheduler statistics
SCHEDULER_STATS=$(grep -A 10 "total paths" "$SCHEDULER_DIR/main/fuzzer_stats")
echo "$SCHEDULER_STATS" >> "$REPORT_DIR/summary.txt"

# Calculate improvement percentages
BASELINE_PATHS=$(grep "total paths" "$BASELINE_DIR/main/fuzzer_stats" | awk '{print $3}')
SCHEDULER_PATHS=$(grep "total paths" "$SCHEDULER_DIR/main/fuzzer_stats" | awk '{print $3}')
BASELINE_EXECS=$(grep "execs_done" "$BASELINE_DIR/main/fuzzer_stats" | awk '{print $3}')
SCHEDULER_EXECS=$(grep "execs_done" "$SCHEDULER_DIR/main/fuzzer_stats" | awk '{print $3}')
BASELINE_CRASHES=$(grep "unique_crashes" "$BASELINE_DIR/main/fuzzer_stats" | awk '{print $3}')
SCHEDULER_CRASHES=$(grep "unique_crashes" "$SCHEDULER_DIR/main/fuzzer_stats" | awk '{print $3}')

PATH_IMPROVEMENT=$(echo "scale=2; ($SCHEDULER_PATHS - $BASELINE_PATHS) * 100 / $BASELINE_PATHS" | bc)
EXEC_IMPROVEMENT=$(echo "scale=2; ($SCHEDULER_EXECS - $BASELINE_EXECS) * 100 / $BASELINE_EXECS" | bc)
CRASH_IMPROVEMENT=$(echo "scale=2; ($SCHEDULER_CRASHES - $BASELINE_CRASHES) * 100 / $BASELINE_CRASHES" | bc 2>/dev/null || echo "N/A")

echo -e "\nPerformance Comparison:\n----------------------" >> "$REPORT_DIR/summary.txt"
echo "Paths found improvement: $PATH_IMPROVEMENT%" >> "$REPORT_DIR/summary.txt"
echo "Executions improvement: $EXEC_IMPROVEMENT%" >> "$REPORT_DIR/summary.txt"
echo "Crashes improvement: $CRASH_IMPROVEMENT%" >> "$REPORT_DIR/summary.txt"

echo "=== Comparison completed ==="
echo "Results are available in $REPORT_DIR"
echo "Summary report: $REPORT_DIR/summary.txt"
