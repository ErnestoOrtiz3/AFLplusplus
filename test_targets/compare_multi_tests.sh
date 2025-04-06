#!/bin/bash
# Script to run and compare tests with and without scheduler feedback

# Default settings
DURATION=600  # 10 minutes by default
NUM_INSTANCES=4  # Number of AFL++ instances to run
BASE_OUTPUT_DIR="./output_comparison"
BASE_METRICS_DIR="./metrics_comparison"

# Parse command line arguments
while getopts "d:n:o:m:" opt; do
    case $opt in
        d) DURATION="$OPTARG" ;;
        n) NUM_INSTANCES="$OPTARG" ;;
        o) BASE_OUTPUT_DIR="$OPTARG" ;;
        m) BASE_METRICS_DIR="$OPTARG" ;;
        *) echo "Usage: $0 [-d DURATION] [-n NUM_INSTANCES] [-o BASE_OUTPUT_DIR] [-m BASE_METRICS_DIR]"; exit 1 ;;
    esac
done

# Create base directories
mkdir -p "$BASE_OUTPUT_DIR" "$BASE_METRICS_DIR"

# Run test with scheduler feedback
echo "=== Running test with scheduler feedback ==="
OUTPUT_DIR="$BASE_OUTPUT_DIR/with_feedback"
METRICS_DIR="$BASE_METRICS_DIR/with_feedback"
mkdir -p "$OUTPUT_DIR" "$METRICS_DIR"

./run_multi_feedback_test.sh -d "$DURATION" -n "$NUM_INSTANCES" -o "$OUTPUT_DIR" -m "$METRICS_DIR" -f 1

# Run test without scheduler feedback
echo "=== Running test without scheduler feedback ==="
OUTPUT_DIR="$BASE_OUTPUT_DIR/without_feedback"
METRICS_DIR="$BASE_METRICS_DIR/without_feedback"
mkdir -p "$OUTPUT_DIR" "$METRICS_DIR"

./run_multi_feedback_test.sh -d "$DURATION" -n "$NUM_INSTANCES" -o "$OUTPUT_DIR" -m "$METRICS_DIR" -f 0

# Generate comparison report
echo "=== Generating comparison report ==="
REPORT_FILE="$BASE_OUTPUT_DIR/comparison_report.txt"

echo "AFL++ Scheduler Comparison Report" > "$REPORT_FILE"
echo "===============================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"
echo "Test configuration:" >> "$REPORT_FILE"
echo "  Duration: $DURATION seconds" >> "$REPORT_FILE"
echo "  Number of instances: $NUM_INSTANCES" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Function to extract metrics from all instances in a test group
extract_group_metrics() {
    local group_dir=$1
    local prefix=$2
    local total_execs=0
    local total_paths=0
    local total_crashes=0
    local total_hangs=0
    local total_bitmap_cvg=0
    local avg_bitmap_cvg=0
    local instances_found=0

    echo "Extracting metrics from $group_dir with prefix $prefix"

    # Extract metrics from each instance
    for i in $(seq 0 $(($NUM_INSTANCES-1))); do
        local instance_dir="$group_dir/${prefix}$i"
        local stats_file="$instance_dir/fuzzer_stats"

        if [ -f "$stats_file" ]; then
            # Extract metrics
            local execs=$(grep "execs_done" "$stats_file" 2>/dev/null | awk '{print $3}')
            local paths=$(grep "paths_total" "$stats_file" 2>/dev/null | awk '{print $3}')
            local crashes=$(grep "unique_crashes" "$stats_file" 2>/dev/null | awk '{print $3}')
            local hangs=$(grep "unique_hangs" "$stats_file" 2>/dev/null | awk '{print $3}')
            local bitmap_cvg=$(grep "bitmap_cvg" "$stats_file" 2>/dev/null | awk '{print $3}' | sed 's/%//')

            # Add to totals
            total_execs=$((total_execs + ${execs:-0}))
            total_paths=$((total_paths + ${paths:-0}))
            total_crashes=$((total_crashes + ${crashes:-0}))
            total_hangs=$((total_hangs + ${hangs:-0}))
            total_bitmap_cvg=$(echo "$total_bitmap_cvg + ${bitmap_cvg:-0}" | bc)

            instances_found=$((instances_found + 1))

            # Log individual instance metrics
            echo "Instance ${prefix}$i:" >> "$REPORT_FILE"
            echo "  Executions: ${execs:-0}" >> "$REPORT_FILE"
            echo "  Paths found: ${paths:-0}" >> "$REPORT_FILE"
            echo "  Crashes found: ${crashes:-0}" >> "$REPORT_FILE"
            echo "  Hangs found: ${hangs:-0}" >> "$REPORT_FILE"
            echo "  Bitmap coverage: ${bitmap_cvg:-0}%" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        else
            echo "Warning: Stats file not found for ${prefix}$i in $group_dir"
        fi
    done

    # Calculate average bitmap coverage
    if [ "$instances_found" -gt 0 ]; then
        avg_bitmap_cvg=$(echo "scale=2; $total_bitmap_cvg / $instances_found" | bc)
    fi

    # Return the metrics as a comma-separated string
    echo "$total_execs,$total_paths,$total_crashes,$total_hangs,$avg_bitmap_cvg"
}

# Extract metrics from with_feedback test
echo "Extracting metrics from with_feedback test..."
WITH_FEEDBACK_METRICS=$(extract_group_metrics "$OUTPUT_DIR/with_feedback" "scheduler")
WITH_FEEDBACK_EXECS=$(echo "$WITH_FEEDBACK_METRICS" | cut -d',' -f1)
WITH_FEEDBACK_PATHS=$(echo "$WITH_FEEDBACK_METRICS" | cut -d',' -f2)
WITH_FEEDBACK_CRASHES=$(echo "$WITH_FEEDBACK_METRICS" | cut -d',' -f3)
WITH_FEEDBACK_HANGS=$(echo "$WITH_FEEDBACK_METRICS" | cut -d',' -f4)
WITH_FEEDBACK_BITMAP_CVG=$(echo "$WITH_FEEDBACK_METRICS" | cut -d',' -f5)

# Extract metrics from without_feedback test
echo "Extracting metrics from without_feedback test..."
WITHOUT_FEEDBACK_METRICS=$(extract_group_metrics "$OUTPUT_DIR/without_feedback" "fuzzer")
WITHOUT_FEEDBACK_EXECS=$(echo "$WITHOUT_FEEDBACK_METRICS" | cut -d',' -f1)
WITHOUT_FEEDBACK_PATHS=$(echo "$WITHOUT_FEEDBACK_METRICS" | cut -d',' -f2)
WITHOUT_FEEDBACK_CRASHES=$(echo "$WITHOUT_FEEDBACK_METRICS" | cut -d',' -f3)
WITHOUT_FEEDBACK_HANGS=$(echo "$WITHOUT_FEEDBACK_METRICS" | cut -d',' -f4)
WITHOUT_FEEDBACK_BITMAP_CVG=$(echo "$WITHOUT_FEEDBACK_METRICS" | cut -d',' -f5)

# Write comparison to report
echo "=== Aggregate Results ===" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "With Scheduler Feedback:" >> "$REPORT_FILE"
echo "  Total executions: ${WITH_FEEDBACK_EXECS:-0}" >> "$REPORT_FILE"
echo "  Total paths found: ${WITH_FEEDBACK_PATHS:-0}" >> "$REPORT_FILE"
echo "  Total crashes found: ${WITH_FEEDBACK_CRASHES:-0}" >> "$REPORT_FILE"
echo "  Total hangs found: ${WITH_FEEDBACK_HANGS:-0}" >> "$REPORT_FILE"
echo "  Average bitmap coverage: ${WITH_FEEDBACK_BITMAP_CVG:-0}%" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "Without Scheduler Feedback:" >> "$REPORT_FILE"
echo "  Total executions: ${WITHOUT_FEEDBACK_EXECS:-0}" >> "$REPORT_FILE"
echo "  Total paths found: ${WITHOUT_FEEDBACK_PATHS:-0}" >> "$REPORT_FILE"
echo "  Total crashes found: ${WITHOUT_FEEDBACK_CRASHES:-0}" >> "$REPORT_FILE"
echo "  Total hangs found: ${WITHOUT_FEEDBACK_HANGS:-0}" >> "$REPORT_FILE"
echo "  Average bitmap coverage: ${WITHOUT_FEEDBACK_BITMAP_CVG:-0}%" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "=== Performance Comparison ===" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Calculate improvements
if [ -n "$WITH_FEEDBACK_EXECS" ] && [ -n "$WITHOUT_FEEDBACK_EXECS" ] && [ "$WITHOUT_FEEDBACK_EXECS" -ne 0 ]; then
    EXECS_IMPROVEMENT=$(echo "scale=2; (${WITH_FEEDBACK_EXECS} - ${WITHOUT_FEEDBACK_EXECS}) * 100 / ${WITHOUT_FEEDBACK_EXECS}" | bc)
    echo "Executions improvement: ${EXECS_IMPROVEMENT}%" >> "$REPORT_FILE"
fi

if [ -n "$WITH_FEEDBACK_PATHS" ] && [ -n "$WITHOUT_FEEDBACK_PATHS" ] && [ "$WITHOUT_FEEDBACK_PATHS" -ne 0 ]; then
    PATHS_IMPROVEMENT=$(echo "scale=2; (${WITH_FEEDBACK_PATHS} - ${WITHOUT_FEEDBACK_PATHS}) * 100 / ${WITHOUT_FEEDBACK_PATHS}" | bc)
    echo "Paths improvement: ${PATHS_IMPROVEMENT}%" >> "$REPORT_FILE"
fi

if [ -n "$WITH_FEEDBACK_CRASHES" ] && [ -n "$WITHOUT_FEEDBACK_CRASHES" ] && [ "$WITHOUT_FEEDBACK_CRASHES" -ne 0 ]; then
    CRASHES_IMPROVEMENT=$(echo "scale=2; (${WITH_FEEDBACK_CRASHES} - ${WITHOUT_FEEDBACK_CRASHES}) * 100 / ${WITHOUT_FEEDBACK_CRASHES}" | bc)
    echo "Crashes improvement: ${CRASHES_IMPROVEMENT}%" >> "$REPORT_FILE"
fi

if [ -n "$WITH_FEEDBACK_BITMAP_CVG" ] && [ -n "$WITHOUT_FEEDBACK_BITMAP_CVG" ] && [ "$(echo "$WITHOUT_FEEDBACK_BITMAP_CVG > 0" | bc)" -eq 1 ]; then
    BITMAP_IMPROVEMENT=$(echo "scale=2; (${WITH_FEEDBACK_BITMAP_CVG} - ${WITHOUT_FEEDBACK_BITMAP_CVG}) * 100 / ${WITHOUT_FEEDBACK_BITMAP_CVG}" | bc)
    echo "Bitmap coverage improvement: ${BITMAP_IMPROVEMENT}%" >> "$REPORT_FILE"
fi

echo "" >> "$REPORT_FILE"
echo "Note: Negative percentages indicate a degradation in performance." >> "$REPORT_FILE"

# Generate comparison plots if gnuplot is available
if command -v gnuplot &> /dev/null; then
    echo "Generating comparison plots..."

    # Plot total executions comparison
    gnuplot <<EOF
    set terminal png size 800,600
    set output "$BASE_METRICS_DIR/execs_comparison.png"
    set title "Total Executions Comparison"
    set xlabel "Time (s)"
    set ylabel "Executions"
    set grid
    set key outside
    plot "$BASE_METRICS_DIR/with_feedback/aggregate_metrics.csv" using 1:2 with lines title "With Feedback", \
         "$BASE_METRICS_DIR/without_feedback/aggregate_metrics.csv" using 1:2 with lines title "Without Feedback"
EOF

    # Plot total paths comparison
    gnuplot <<EOF
    set terminal png size 800,600
    set output "$BASE_METRICS_DIR/paths_comparison.png"
    set title "Total Paths Comparison"
    set xlabel "Time (s)"
    set ylabel "Paths"
    set grid
    set key outside
    plot "$BASE_METRICS_DIR/with_feedback/aggregate_metrics.csv" using 1:3 with lines title "With Feedback", \
         "$BASE_METRICS_DIR/without_feedback/aggregate_metrics.csv" using 1:3 with lines title "Without Feedback"
EOF

    echo "Comparison plots generated in $BASE_METRICS_DIR"
fi

echo "Comparison completed!"
echo "Results are available in $BASE_OUTPUT_DIR"
echo "Metrics are available in $BASE_METRICS_DIR"
echo "Comparison report: $REPORT_FILE"
