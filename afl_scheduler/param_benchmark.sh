#!/bin/bash
#
# Script to benchmark the parameterized AFL++ CPU Scheduler with different parameters
#

# Default benchmark parameters
DURATION=1
NUM_INSTANCES=4
TARGET_PROGRAM="./complex_target_afl"
TARGET_ARGS="@@"
MEMORY_LIMIT="none"
TIMEOUT="7500+"
SCHEDULER_ORDER="custom_first"

# Function to run a benchmark with specific parameters
run_benchmark() {
    local test_name="$1"
    local boost_duration="$2"
    local boost_weight="$3"
    local poll_interval="$4"
    local weight_scale="$5"
    local decay_factor="$6"
    
    echo "=== Running benchmark: $test_name ==="
    echo "Parameters:"
    echo "  Boost duration: $boost_duration us"
    echo "  Boost weight: $boost_weight"
    echo "  Poll interval: $poll_interval ms"
    echo "  Weight scale: $weight_scale"
    echo "  Decay factor: $decay_factor"
    
    # Create a unique results directory for this test
    local results_dir="benchmark_results_${test_name}"
    
    # Save parameter information
    mkdir -p "$results_dir"
    echo "Test: $test_name" > "$results_dir/parameters.txt"
    echo "Boost duration: $boost_duration us" >> "$results_dir/parameters.txt"
    echo "Boost weight: $boost_weight" >> "$results_dir/parameters.txt"
    echo "Poll interval: $poll_interval ms" >> "$results_dir/parameters.txt"
    echo "Weight scale: $weight_scale" >> "$results_dir/parameters.txt"
    echo "Decay factor: $decay_factor" >> "$results_dir/parameters.txt"
    
    # Modify the benchmark_direct.sh script to use our parameterized scheduler
    # We'll create a temporary copy of the script with modifications
    cp afl_scheduler/benchmark_direct.sh afl_scheduler/benchmark_param_temp.sh
    chmod +x afl_scheduler/benchmark_param_temp.sh
    
    # Replace the scheduler loading code in the temporary script
    sed -i "s|sudo ./afl_sched_loader|sudo ./afl_sched_loader_param -b $boost_duration -s 20000 -m 5000|g" afl_scheduler/benchmark_param_temp.sh
    sed -i "s|./afl_monitor_direct|./afl_monitor_param -i $poll_interval -w $weight_scale -d $decay_factor -b $boost_weight -t $boost_duration|g" afl_scheduler/benchmark_param_temp.sh
    
    # Run the modified benchmark script
    sudo ./afl_scheduler/benchmark_param_temp.sh $DURATION $NUM_INSTANCES $TARGET_PROGRAM $TARGET_ARGS $SCHEDULER_ORDER $MEMORY_LIMIT $TIMEOUT
    
    # Copy results to our test-specific directory
    cp -r benchmark_results/* "$results_dir/"
    
    # Clean up
    rm afl_scheduler/benchmark_param_temp.sh
    
    echo "Benchmark completed. Results in $results_dir/"
    echo ""
}

# Function to run multiple benchmarks and generate a summary report
run_all_benchmarks() {
    # Create a directory for the summary report
    mkdir -p "param_benchmark_summary"
    
    # Run benchmarks with different parameter combinations
    run_benchmark "baseline" 1000000 1000 1000 10 0.99
    run_benchmark "boost_duration" 3000000 1000 1000 10 0.99
    run_benchmark "boost_weight" 1000000 3000 1000 10 0.99
    run_benchmark "boost_duration_weight" 3000000 3000 1000 10 0.99
    run_benchmark "weight_scale" 1000000 1000 1000 20 0.99
    run_benchmark "decay_factor" 1000000 1000 1000 10 0.95
    run_benchmark "optimized" 3000000 3000 1500 20 0.95
    
    # Generate summary report
    echo "=== Parameter Benchmark Summary ===" > "param_benchmark_summary/summary.txt"
    echo "" >> "param_benchmark_summary/summary.txt"
    
    # Extract key metrics from each benchmark
    for test_dir in benchmark_results_*/; do
        test_name=$(basename "$test_dir")
        echo "=== $test_name ===" >> "param_benchmark_summary/summary.txt"
        
        # Add parameters
        cat "$test_dir/parameters.txt" >> "param_benchmark_summary/summary.txt"
        echo "" >> "param_benchmark_summary/summary.txt"
        
        # Add key metrics from comparison report
        if [ -f "$test_dir/comparison_report.txt" ]; then
            grep -A 6 "Overall Performance" "$test_dir/comparison_report.txt" >> "param_benchmark_summary/summary.txt"
        else
            echo "No comparison report found" >> "param_benchmark_summary/summary.txt"
        fi
        
        echo "" >> "param_benchmark_summary/summary.txt"
        echo "" >> "param_benchmark_summary/summary.txt"
    done
    
    echo "All benchmarks completed. Summary in param_benchmark_summary/summary.txt"
}

# Function to run a single benchmark with custom parameters
run_custom_benchmark() {
    if [ $# -ne 6 ]; then
        echo "Usage: $0 custom <test_name> <boost_duration> <boost_weight> <poll_interval> <weight_scale> <decay_factor>"
        exit 1
    fi
    
    local test_name="$2"
    local boost_duration="$3"
    local boost_weight="$4"
    local poll_interval="$5"
    local weight_scale="$6"
    local decay_factor="$7"
    
    run_benchmark "$test_name" "$boost_duration" "$boost_weight" "$poll_interval" "$weight_scale" "$decay_factor"
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
        echo "Usage: $0 [custom <test_name> <boost_duration> <boost_weight> <poll_interval> <weight_scale> <decay_factor>]"
        exit 1
    fi
}

# Run the main function
main "$@"
