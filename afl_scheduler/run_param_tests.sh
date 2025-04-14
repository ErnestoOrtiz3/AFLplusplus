#!/bin/bash
#
# Script to run multiple parameter tests for the AFL++ CPU Scheduler
#

# Base directory for test results
BASE_DIR="param_test_results"
mkdir -p "$BASE_DIR"

# Default benchmark parameters
DURATION=1
NUM_INSTANCES=4
TARGET_PROGRAM="./complex_target_afl"
TARGET_ARGS="@@"
MEMORY_LIMIT="none"
TIMEOUT="7500+"
SCHEDULER_ORDER="custom_first"

# Function to run a test with specific parameters
run_test() {
    local test_name="$1"
    local boost_duration="$2"
    local boost_weight="$3"
    local poll_interval="$4"
    local weight_scale="$5"
    local decay_factor="$6"
    
    echo "=== Running test: $test_name ==="
    echo "Parameters:"
    echo "  Boost duration: $boost_duration us"
    echo "  Boost weight: $boost_weight"
    echo "  Poll interval: $poll_interval ms"
    echo "  Weight scale: $weight_scale"
    echo "  Decay factor: $decay_factor"
    
    # Run the test
    ./afl_scheduler/test_param_scheduler.sh \
        --duration "$DURATION" \
        --num-instances "$NUM_INSTANCES" \
        --target "$TARGET_PROGRAM" \
        --args "$TARGET_ARGS" \
        --memory-limit "$MEMORY_LIMIT" \
        --timeout "$TIMEOUT" \
        --scheduler-order "$SCHEDULER_ORDER" \
        --boost-duration "$boost_duration" \
        --boost-weight "$boost_weight" \
        --poll-interval "$poll_interval" \
        --weight-scale "$weight_scale" \
        --decay-factor "$decay_factor"
    
    echo "Test completed."
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

for test_dir in "${BASE_DIR}"/test_*/; do
    if [ -f "${test_dir}/comparison.txt" ]; then
        cat "${test_dir}/comparison.txt" >> "${BASE_DIR}/summary.txt"
        echo "" >> "${BASE_DIR}/summary.txt"
        echo "" >> "${BASE_DIR}/summary.txt"
    fi
done

echo "All tests completed. Summary in ${BASE_DIR}/summary.txt"
