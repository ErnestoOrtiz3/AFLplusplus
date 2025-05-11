#!/bin/bash
#
# Script to run the same parameter test multiple times
# Each run will have its own separate results directory
#

# Configuration
NUM_RUNS=1
TEST_NAME="enhanced_optimal_test"
BOOST_DURATION=500000
BOOST_WEIGHT=600
BOOST_DECAY=5000000
SLICE_US=10000
SLICE_MIN_US=2000

# Check if we have sudo access
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run with sudo. Please run with: sudo $0"
    exit 1
fi

# Create a directory to store all test results
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="multiple_test_results_${TIMESTAMP}"
mkdir -p "$RESULTS_DIR"

# Save test configuration
echo "Test Configuration:" > "$RESULTS_DIR/config.txt"
echo "Test name: $TEST_NAME" >> "$RESULTS_DIR/config.txt"
echo "Boost duration: $BOOST_DURATION" >> "$RESULTS_DIR/config.txt"
echo "Boost weight: $BOOST_WEIGHT" >> "$RESULTS_DIR/config.txt"
echo "Boost decay: $BOOST_DECAY" >> "$RESULTS_DIR/config.txt"
echo "Slice us: $SLICE_US" >> "$RESULTS_DIR/config.txt"
echo "Slice min us: $SLICE_MIN_US" >> "$RESULTS_DIR/config.txt"
echo "Number of runs: $NUM_RUNS" >> "$RESULTS_DIR/config.txt"
echo "Started at: $(date)" >> "$RESULTS_DIR/config.txt"

# Function to run a single test
run_single_test() {
    local run_number=$1
    local run_name="${TEST_NAME}${run_number}"

    echo "=== Starting run $run_number of $NUM_RUNS ==="
    echo "Run name: $run_name"
    echo "Started at: $(date)"

    # Run the test
    ./afl_scheduler/param_test_enhanced_fixed.sh custom "$run_name" "$BOOST_DURATION" "$BOOST_WEIGHT" "$BOOST_DECAY" "$SLICE_US" "$SLICE_MIN_US"

    # Find the results directory for this run
    local results_dir=""

    # First check if the directory exists directly (new method)
    if [ -d "$run_name" ]; then
        results_dir="$run_name"
    else
        # Fall back to old method
        results_dir=$(find enhanced_param_tests_* -type d -name "$run_name" | sort -r | head -n 1)
    fi

    if [ -n "$results_dir" ]; then
        # Copy the comparison report to our results directory
        mkdir -p "$RESULTS_DIR/run_$run_number"
        cp "$results_dir/comparison_report.txt" "$RESULTS_DIR/run_$run_number/"

        # Extract key metrics for summary
        echo "Run $run_number results:" >> "$RESULTS_DIR/summary.txt"
        grep -A 6 "Overall Performance" "$results_dir/comparison_report.txt" >> "$RESULTS_DIR/summary.txt"
        echo "" >> "$RESULTS_DIR/summary.txt"

        echo "Results saved to $RESULTS_DIR/run_$run_number/"
    else
        echo "Warning: Could not find results directory for run $run_number"
        echo "Run $run_number: No results found" >> "$RESULTS_DIR/summary.txt"
        echo "" >> "$RESULTS_DIR/summary.txt"
    fi

    echo "Completed at: $(date)"
    echo "=== Finished run $run_number of $NUM_RUNS ==="
    echo ""
}

# Initialize summary file
echo "Summary of $NUM_RUNS runs with optimal parameters" > "$RESULTS_DIR/summary.txt"
echo "Test name: $TEST_NAME" >> "$RESULTS_DIR/summary.txt"
echo "Parameters: boost_duration=$BOOST_DURATION, boost_weight=$BOOST_WEIGHT, boost_decay=$BOOST_DECAY, slice_us=$SLICE_US, slice_min_us=$SLICE_MIN_US" >> "$RESULTS_DIR/summary.txt"
echo "Started at: $(date)" >> "$RESULTS_DIR/summary.txt"
echo "" >> "$RESULTS_DIR/summary.txt"

# Run the tests
for i in $(seq 1 $NUM_RUNS); do
    run_single_test $i
done

# Finalize summary
echo "" >> "$RESULTS_DIR/summary.txt"
echo "Completed at: $(date)" >> "$RESULTS_DIR/summary.txt"

# Calculate average metrics
echo "" >> "$RESULTS_DIR/summary.txt"
echo "Average metrics across all runs:" >> "$RESULTS_DIR/summary.txt"

# Extract and calculate averages for each metric
metrics=("Total executions/sec" "Total paths found" "Total crashes found" "Total edges found" "Average bitmap coverage")

for metric in "${metrics[@]}"; do
    # Extract all values for this metric
    custom_values=$(grep "$metric: Custom=" "$RESULTS_DIR/run_"*/comparison_report.txt | sed -E "s/.*Custom=([0-9.]+).*/\1/")
    EEVDF_values=$(grep "$metric: .*EEVDF=" "$RESULTS_DIR/run_"*/comparison_report.txt | sed -E "s/.*EEVDF=([0-9.]+).*/\1/")
    diff_values=$(grep "$metric: .*Diff=" "$RESULTS_DIR/run_"*/comparison_report.txt | sed -E "s/.*Diff=([0-9.+-]+)%.*/\1/")

    # Calculate averages
    custom_avg=$(echo "$custom_values" | awk '{ sum += $1; n++ } END { if (n > 0) print sum / n; else print "N/A" }')
    EEVDF_avg=$(echo "$EEVDF_values" | awk '{ sum += $1; n++ } END { if (n > 0) print sum / n; else print "N/A" }')
    diff_avg=$(echo "$diff_values" | awk '{ sum += $1; n++ } END { if (n > 0) print sum / n; else print "N/A" }')

    # Calculate difference percentage from the averages directly
    if [[ "$custom_avg" != "N/A" && "$EEVDF_avg" != "N/A" && "$EEVDF_avg" != "0" ]]; then
        recalc_diff=$(echo "scale=4; ($custom_avg - $EEVDF_avg) * 100 / $EEVDF_avg" | bc)
    else
        recalc_diff="N/A"
    fi

    # Add to summary
    echo "$metric: Custom=$custom_avg, EEVDF=$EEVDF_avg, Diff=$diff_avg% (Recalculated Diff=$recalc_diff%)" >> "$RESULTS_DIR/summary.txt"
done

echo ""
echo "All tests completed!"
echo "Results saved to $RESULTS_DIR/"
echo "Summary available at $RESULTS_DIR/summary.txt"
