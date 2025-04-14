#!/bin/bash
#
# Script to test different parameters of the enhanced AFL++ CPU Scheduler
#

# Default benchmark parameters
DURATION=1
NUM_INSTANCES=4
TARGET_PROGRAM="./complex_target_afl"
TARGET_ARGS="@@"
MEMORY_LIMIT="none"
TIMEOUT="7500+"
SCHEDULER_ORDER="custom_first"

# Base directory for all results
BASE_RESULTS_DIR="enhanced_param_tests_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$BASE_RESULTS_DIR"

# Function to run a benchmark with specific parameters
run_benchmark() {
    local test_name="$1"
    local boost_duration="$2"
    local boost_weight="$3"
    local boost_decay="$4"
    local slice_us="$5"
    local slice_min_us="$6"
    
    echo "=== Running benchmark: $test_name ==="
    echo "Parameters:"
    echo "  Boost duration: $boost_duration us"
    echo "  Boost weight: $boost_weight"
    echo "  Boost decay: $boost_decay us"
    echo "  Time slice: $slice_us us"
    echo "  Minimum time slice: $slice_min_us us"
    
    # Create a unique results directory for this test
    local results_dir="$BASE_RESULTS_DIR/$test_name"
    
    # Save parameter information
    mkdir -p "$results_dir"
    echo "Test: $test_name" > "$results_dir/parameters.txt"
    echo "Boost duration: $boost_duration us" >> "$results_dir/parameters.txt"
    echo "Boost weight: $boost_weight" >> "$results_dir/parameters.txt"
    echo "Boost decay: $boost_decay us" >> "$results_dir/parameters.txt"
    echo "Time slice: $slice_us us" >> "$results_dir/parameters.txt"
    echo "Minimum time slice: $slice_min_us us" >> "$results_dir/parameters.txt"
    
    # Run the benchmark with these parameters
    sudo /home/ernesto/Documents/AFLplusplus/afl_scheduler/enhanced_simple_benchmark_fixed.sh \
        --duration "$DURATION" \
        --num-instances "$NUM_INSTANCES" \
        --target "$TARGET_PROGRAM" \
        --args "$TARGET_ARGS" \
        --memory-limit "$MEMORY_LIMIT" \
        --timeout "$TIMEOUT" \
        --scheduler-order "$SCHEDULER_ORDER" \
        --boost-duration "$boost_duration" \
        --boost-weight "$boost_weight" \
        --boost-decay "$boost_decay" \
        --slice "$slice_us" \
        --min-slice "$slice_min_us"
    
    # Copy the comparison report to our test directory
    cp enhanced_simple_benchmark_latest.txt "$results_dir/comparison_report.txt"
    
    echo "Benchmark completed. Results in $results_dir/"
    echo ""
}

# Function to run multiple benchmarks and generate a summary report
run_all_benchmarks() {
    # Create a directory for the summary report
    mkdir -p "$BASE_RESULTS_DIR/summary"
    
    # Run benchmarks with different parameter combinations
    
    # Baseline test with default parameters
    run_benchmark "baseline" 1000000 1000 2000000 20000 5000
    
    # Test different boost durations
    run_benchmark "boost_duration_short" 500000 1000 2000000 20000 5000
    run_benchmark "boost_duration_long" 3000000 1000 2000000 20000 5000
    
    # Test different boost weights
    run_benchmark "boost_weight_low" 1000000 500 2000000 20000 5000
    run_benchmark "boost_weight_high" 1000000 3000 2000000 20000 5000
    
    # Test different boost decay periods
    run_benchmark "boost_decay_short" 1000000 1000 1000000 20000 5000
    run_benchmark "boost_decay_long" 1000000 1000 5000000 20000 5000
    
    # Test different time slices
    run_benchmark "slice_short" 1000000 1000 2000000 10000 5000
    run_benchmark "slice_long" 1000000 1000 2000000 40000 5000
    
    # Test different minimum time slices
    run_benchmark "min_slice_low" 1000000 1000 2000000 20000 2000
    run_benchmark "min_slice_high" 1000000 1000 2000000 20000 10000
    
    # Test combinations of parameters
    run_benchmark "high_boost_long_decay" 1000000 3000 5000000 20000 5000
    run_benchmark "long_boost_high_weight" 3000000 3000 2000000 20000 5000
    run_benchmark "optimized" 3000000 3000 5000000 30000 5000
    
    # Generate summary report
    echo "=== Enhanced Scheduler Parameter Test Summary ===" > "$BASE_RESULTS_DIR/summary/summary.txt"
    echo "" >> "$BASE_RESULTS_DIR/summary/summary.txt"
    
    # Extract key metrics from each benchmark
    for test_dir in "$BASE_RESULTS_DIR"/*; do
        if [ -d "$test_dir" ] && [ "$(basename "$test_dir")" != "summary" ]; then
            test_name=$(basename "$test_dir")
            echo "=== $test_name ===" >> "$BASE_RESULTS_DIR/summary/summary.txt"
            
            # Add parameters
            cat "$test_dir/parameters.txt" >> "$BASE_RESULTS_DIR/summary/summary.txt"
            echo "" >> "$BASE_RESULTS_DIR/summary/summary.txt"
            
            # Add key metrics from comparison report
            if [ -f "$test_dir/comparison_report.txt" ]; then
                grep -A 6 "Overall Performance" "$test_dir/comparison_report.txt" >> "$BASE_RESULTS_DIR/summary/summary.txt"
            else
                echo "No comparison report found" >> "$BASE_RESULTS_DIR/summary/summary.txt"
            fi
            
            echo "" >> "$BASE_RESULTS_DIR/summary/summary.txt"
            echo "" >> "$BASE_RESULTS_DIR/summary/summary.txt"
        fi
    done
    
    # Copy summary to an easily accessible location
    cp "$BASE_RESULTS_DIR/summary/summary.txt" "enhanced_param_tests_summary.txt"
    
    echo "All benchmarks completed. Summary in $BASE_RESULTS_DIR/summary/summary.txt"
    echo "Summary also available at: enhanced_param_tests_summary.txt"
}

# Function to run a single benchmark with custom parameters
run_custom_benchmark() {
    if [ $# -ne 6 ]; then
        echo "Usage: $0 custom <test_name> <boost_duration> <boost_weight> <boost_decay> <slice_us> <slice_min_us>"
        exit 1
    fi
    
    local test_name="$2"
    local boost_duration="$3"
    local boost_weight="$4"
    local boost_decay="$5"
    local slice_us="$6"
    local slice_min_us="$7"
    
    run_benchmark "$test_name" "$boost_duration" "$boost_weight" "$boost_decay" "$slice_us" "$slice_min_us"
}

# Main function
main() {
    if [ $# -eq 0 ]; then
        # No arguments, run all benchmarks
        run_all_benchmarks
    elif [ "$1" = "custom" ]; then
        # Custom benchmark with specific parameters
        run_custom_benchmark "$@"
    else
        echo "Usage: $0 [custom <test_name> <boost_duration> <boost_weight> <boost_decay> <slice_us> <slice_min_us>]"
        exit 1
    fi
}

# Run the main function
main "$@"
