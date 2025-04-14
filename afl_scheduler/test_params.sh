#!/bin/bash
#
# Script to test different parameter combinations for the AFL++ CPU Scheduler
#

# Base directory for test results
BASE_DIR="param_test_results"
mkdir -p "$BASE_DIR"

# Benchmark script path
BENCHMARK_SCRIPT="./afl_scheduler/benchmark_direct.sh"

# Default benchmark parameters
DURATION=20
NUM_INSTANCES=4
TARGET_PROGRAM="./complex_target_afl"
TARGET_ARGS="@@"
SCHEDULER_ORDER="custom_first"
MEMORY_LIMIT="none"
TIMEOUT="7500+"

# Function to run a test with specific parameters
run_test() {
    local test_name="$1"
    local boost_duration="$2"
    local boost_weight="$3"
    local poll_interval="$4"
    local weight_scale="$5"
    local decay_factor="$6"
    
    local test_dir="${BASE_DIR}/${test_name}"
    mkdir -p "$test_dir"
    
    echo "=== Running test: $test_name ==="
    echo "Parameters:"
    echo "  Boost duration: $boost_duration us"
    echo "  Boost weight: $boost_weight"
    echo "  Poll interval: $poll_interval ms"
    echo "  Weight scale: $weight_scale"
    echo "  Decay factor: $decay_factor"
    
    # Start the scheduler with the specified parameters
    sudo ./afl_scheduler/afl_sched_ctl_param.sh start \
        --boost-duration "$boost_duration" \
        --boost-weight "$boost_weight" \
        --poll-interval "$poll_interval" \
        --weight-scale "$weight_scale" \
        --decay-factor "$decay_factor"
    
    # Run the benchmark
    sudo "$BENCHMARK_SCRIPT" "$DURATION" "$NUM_INSTANCES" "$TARGET_PROGRAM" "$TARGET_ARGS" "$SCHEDULER_ORDER" "$MEMORY_LIMIT" "$TIMEOUT"
    
    # Stop the scheduler
    sudo ./afl_scheduler/afl_sched_ctl_param.sh stop
    
    # Copy results to test directory
    cp -r benchmark_results/* "$test_dir/"
    
    # Extract key metrics
    grep -A 20 "Overall Performance" "$test_dir/comparison_report.txt" > "$test_dir/summary.txt"
    
    echo "Test completed. Results in $test_dir/"
    echo ""
}

# Test 1: Default parameters (baseline)
run_test "test1_baseline" 1000000 1000 1000 10 0.99

# Test 2: Increased boost duration
run_test "test2_boost_duration" 3000000 1000 1000 10 0.99

# Test 3: Increased boost weight
run_test "test3_boost_weight" 1000000 3000 1000 10 0.99

# Test 4: Increased boost duration and weight
run_test "test4_boost_duration_weight" 3000000 3000 1000 10 0.99

# Test 5: Increased weight scale factor
run_test "test5_weight_scale" 1000000 1000 1000 20 0.99

# Test 6: Slower decay factor
run_test "test6_decay_factor" 1000000 1000 1000 10 0.95

# Test 7: Optimized combination
run_test "test7_optimized" 3000000 3000 1500 20 0.95

# Generate summary report
echo "=== Parameter Test Summary ===" > "${BASE_DIR}/summary.txt"
echo "" >> "${BASE_DIR}/summary.txt"

for test_dir in "${BASE_DIR}"/*/; do
    test_name=$(basename "$test_dir")
    echo "=== $test_name ===" >> "${BASE_DIR}/summary.txt"
    cat "${test_dir}/summary.txt" >> "${BASE_DIR}/summary.txt"
    echo "" >> "${BASE_DIR}/summary.txt"
    echo "" >> "${BASE_DIR}/summary.txt"
done

echo "All tests completed. Summary in ${BASE_DIR}/summary.txt"
