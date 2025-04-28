#!/bin/bash
#
# Script to benchmark the simplified enhanced AFL++ CPU Scheduler
#

# Default benchmark parameters
DURATION=2
NUM_INSTANCES=4
TARGET_PROGRAM="./complex_target_afl"
TARGET_ARGS="@@"
MEMORY_LIMIT="none"
TIMEOUT="7500+"
SCHEDULER_ORDER="custom_first"

# Default scheduler parameters
BOOST_DURATION=1000000  # 1 second in microseconds
BOOST_WEIGHT=1000       # Default boost weight
BOOST_DECAY=2000000     # 2 seconds decay period
SLICE_US=20000          # Default time slice
SLICE_MIN_US=5000       # Minimum time slice

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    -d|--duration)
      DURATION="$2"
      shift 2
      ;;
    -n|--num-instances)
      NUM_INSTANCES="$2"
      shift 2
      ;;
    -t|--target)
      TARGET_PROGRAM="$2"
      shift 2
      ;;
    -a|--args)
      TARGET_ARGS="$2"
      shift 2
      ;;
    -m|--memory-limit)
      MEMORY_LIMIT="$2"
      shift 2
      ;;
    -o|--timeout)
      TIMEOUT="$2"
      shift 2
      ;;
    -s|--scheduler-order)
      SCHEDULER_ORDER="$2"
      shift 2
      ;;
    --boost-duration)
      BOOST_DURATION="$2"
      shift 2
      ;;
    --boost-weight)
      BOOST_WEIGHT="$2"
      shift 2
      ;;
    --boost-decay)
      BOOST_DECAY="$2"
      shift 2
      ;;
    --slice)
      SLICE_US="$2"
      shift 2
      ;;
    --min-slice)
      SLICE_MIN_US="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [options]"
      echo ""
      echo "Benchmark options:"
      echo "  -d, --duration MINUTES       Duration of each test in minutes (default: $DURATION)"
      echo "  -n, --num-instances NUM      Number of AFL++ instances to run (default: $NUM_INSTANCES)"
      echo "  -t, --target PROGRAM         Target program to fuzz (default: $TARGET_PROGRAM)"
      echo "  -a, --args ARGS              Target program arguments (default: $TARGET_ARGS)"
      echo "  -m, --memory-limit LIMIT     Memory limit for AFL++ (default: $MEMORY_LIMIT)"
      echo "  -o, --timeout TIMEOUT        Timeout for AFL++ (default: $TIMEOUT)"
      echo "  -s, --scheduler-order ORDER  Scheduler order: custom_first or cfs_first (default: $SCHEDULER_ORDER)"
      echo ""
      echo "Scheduler parameters:"
      echo "  --boost-duration DURATION    Boost duration in microseconds (default: $BOOST_DURATION)"
      echo "  --boost-weight WEIGHT        Boost weight (default: $BOOST_WEIGHT)"
      echo "  --boost-decay DURATION       Boost decay period in microseconds (default: $BOOST_DECAY)"
      echo "  --slice MICROSECONDS         Time slice in microseconds (default: $SLICE_US)"
      echo "  --min-slice MICROSECONDS     Minimum time slice in microseconds (default: $SLICE_MIN_US)"
      echo ""
      echo "  -h, --help                   Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Create a unique test ID based on parameters and timestamp
TEST_ID="enhanced_simple_$(date +%Y%m%d_%H%M%S)"
RESULTS_DIR="enhanced_simple_benchmark_results/${TEST_ID}"
STATS_DIR="$RESULTS_DIR/stats"

# Create results directory
mkdir -p "$RESULTS_DIR"
mkdir -p "$STATS_DIR/custom"
mkdir -p "$STATS_DIR/cfs"

# Save test parameters
echo "Test ID: $TEST_ID" > "$RESULTS_DIR/parameters.txt"
echo "Duration: $DURATION minutes" >> "$RESULTS_DIR/parameters.txt"
echo "Number of instances: $NUM_INSTANCES" >> "$RESULTS_DIR/parameters.txt"
echo "Target program: $TARGET_PROGRAM" >> "$RESULTS_DIR/parameters.txt"
echo "Target arguments: $TARGET_ARGS" >> "$RESULTS_DIR/parameters.txt"
echo "Memory limit: $MEMORY_LIMIT" >> "$RESULTS_DIR/parameters.txt"
echo "Timeout: $TIMEOUT" >> "$RESULTS_DIR/parameters.txt"
echo "Scheduler order: $SCHEDULER_ORDER" >> "$RESULTS_DIR/parameters.txt"
echo "Boost duration: $BOOST_DURATION us" >> "$RESULTS_DIR/parameters.txt"
echo "Boost weight: $BOOST_WEIGHT" >> "$RESULTS_DIR/parameters.txt"
echo "Boost decay period: $BOOST_DECAY us" >> "$RESULTS_DIR/parameters.txt"
echo "Time slice: $SLICE_US us" >> "$RESULTS_DIR/parameters.txt"
echo "Minimum time slice: $SLICE_MIN_US us" >> "$RESULTS_DIR/parameters.txt"

# Function to run the benchmark with a specific scheduler
run_benchmark() {
    local scheduler="$1"
    
    echo "=== Running benchmark with $scheduler scheduler ==="
    
    if [ "$scheduler" = "custom" ]; then
        # Start the enhanced scheduler
        echo "Starting enhanced scheduler with:"
        echo "  Boost duration: $BOOST_DURATION us"
        echo "  Boost weight: $BOOST_WEIGHT"
        echo "  Boost decay period: $BOOST_DECAY us"
        echo "  Time slice: $SLICE_US us"
        echo "  Minimum time slice: $SLICE_MIN_US us"
        
        # Load the enhanced scheduler
        sudo /home/ernesto/Documents/AFLplusplus/afl_scheduler/afl_sched_loader_enhanced_simple \
            -b "$BOOST_DURATION" \
            -w "$BOOST_WEIGHT" \
            -d "$BOOST_DECAY" \
            -s "$SLICE_US" \
            -m "$SLICE_MIN_US" &
        
        # Wait for scheduler to initialize
        sleep 5
        
        # Check if scheduler is running
        if ! ps aux | grep -q "[a]fl_sched_loader_enhanced_simple"; then
            echo "Error: Failed to start enhanced scheduler"
            return 1
        fi
    fi
    
    # Create output directory
    local output_dir="$RESULTS_DIR/$scheduler"
    mkdir -p "$output_dir"
    
    # Determine which scheduler to run first
    if [ "$SCHEDULER_ORDER" = "custom_first" ]; then
        if [ "$scheduler" = "custom" ]; then
            FIRST_RUN="true"
        else
            FIRST_RUN="false"
        fi
    else
        if [ "$scheduler" = "custom" ]; then
            FIRST_RUN="false"
        else
            FIRST_RUN="true"
        fi
    fi
    
    # Start stats collector
    /home/ernesto/Documents/AFLplusplus/afl_scheduler/stats_collector "$STATS_DIR/$scheduler" &
    STATS_PID=$!
    
    # Start AFL++ instances
    for i in $(seq 1 "$NUM_INSTANCES"); do
        if [ "$i" -eq 1 ]; then
            # First instance is the main node
            AFL_MODE="-M"
        else
            # Other instances are secondary nodes
            AFL_MODE="-S"
        fi
        
        # Start AFL++ instance
        sudo AFL_NO_AFFINITY=1 /home/ernesto/Documents/AFLplusplus/afl-fuzz -i /home/ernesto/Documents/AFLplusplus/original_seeds -o "$output_dir" \
            $AFL_MODE "fuzzer$i" -t "$TIMEOUT" -m "$MEMORY_LIMIT" \
            -- "$TARGET_PROGRAM" "$TARGET_ARGS" &
        
        # Wait a bit to avoid startup race conditions
        sleep 2
    done
    
    # Wait for the specified duration
    echo "Running for $DURATION minutes..."
    sleep $((DURATION * 60))
    
    # Stop AFL++ instances
    echo "Stopping AFL++ instances..."
    sudo killall afl-fuzz
    
    # Wait for all instances to stop
    sleep 5
    
    # Stop stats collector
    kill $STATS_PID
    
    # If using custom scheduler, stop it
    if [ "$scheduler" = "custom" ]; then
        echo "Stopping enhanced scheduler..."
        sudo killall afl_sched_loader_enhanced_simple
        sleep 2
    fi
    
    echo "Benchmark with $scheduler scheduler completed"
}

# Run benchmarks based on scheduler order
if [ "$SCHEDULER_ORDER" = "custom_first" ]; then
    run_benchmark "custom"
    run_benchmark "cfs"
else
    run_benchmark "cfs"
    run_benchmark "custom"
fi

# Generate comparison report
echo "Generating comparison report..."
python3 /home/ernesto/Documents/AFLplusplus/afl_scheduler/compare_results.py "$RESULTS_DIR/custom" "$RESULTS_DIR/cfs" "$STATS_DIR" > "$RESULTS_DIR/comparison_report.txt"

echo "Benchmark completed. Results in $RESULTS_DIR/"
echo "Comparison report: $RESULTS_DIR/comparison_report.txt"

# Copy comparison report to a more accessible location
cp "$RESULTS_DIR/comparison_report.txt" "enhanced_simple_benchmark_latest.txt"
echo "Latest comparison report also available at: enhanced_simple_benchmark_latest.txt"
