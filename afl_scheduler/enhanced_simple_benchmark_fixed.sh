#!/bin/bash
#
# Script to benchmark the simplified enhanced AFL++ CPU Scheduler
#

# Default benchmark parameters
DURATION=1
NUM_INSTANCES=4
TARGET_PROGRAM="./complex_target_afl"
TARGET_ARGS="@@"
MEMORY_LIMIT="none"
TIMEOUT="7500+"
SCHEDULER_ORDER="custom_first"
CUSTOM_RESULTS_DIR=""   # Optional custom results directory
FINAL_RESULTS_DIR=""    # Final destination for essential results

# Default scheduler parameters
BOOST_DURATION=3372000
BOOST_WEIGHT=3000
BOOST_DECAY=3240000
SLICE_US=37000
SLICE_MIN_US=8000

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
    --results-dir)
      CUSTOM_RESULTS_DIR="$2"
      shift 2
      ;;
    --final-results-dir)
      FINAL_RESULTS_DIR="$2"
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
      echo "  -s, --scheduler-order ORDER  Scheduler order: custom_first or EEVDF_first (default: $SCHEDULER_ORDER)"
      echo ""
      echo "Scheduler parameters:"
      echo "  --boost-duration DURATION    Boost duration in microseconds (default: $BOOST_DURATION)"
      echo "  --boost-weight WEIGHT        Boost weight (default: $BOOST_WEIGHT)"
      echo "  --boost-decay DURATION       Boost decay period in microseconds (default: $BOOST_DECAY)"
      echo "  --slice MICROSECONDS         Time slice in microseconds (default: $SLICE_US)"
      echo "  --min-slice MICROSECONDS     Minimum time slice in microseconds (default: $SLICE_MIN_US)"
      echo "  --results-dir DIR            Custom results directory (default: auto-generated)"
      echo "  --final-results-dir DIR      Final destination for essential results"
      echo ""
      echo "Power scheduling:"
      echo "  The script automatically distributes power schedules based on the number of instances:"
      echo "  - First instance: Always uses EXPLORE (-p explore) as the main node"
      echo "  - Remaining instances: Distributed as follows:"
      echo "    * ~30% EXPLOIT (-p exploit): Focuses on exploiting promising paths"
      echo "    * ~30% EXPLORE (-p explore): Balanced exploration and exploitation"
      echo "    * ~20% FAST (-p fast): Quick iteration through test cases"
      echo "    * ~10% RARE (-p rare): Focuses on rare edges in the coverage map"
      echo "    * ~10% CMPLOG (-l 2AT): Uses CMPLOG with transformations (if ≥5 instances)"
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
if [ -z "$CUSTOM_RESULTS_DIR" ]; then
    # No custom directory provided, create a temporary one
    TEST_ID="enhanced_simple_$(date +%Y%m%d_%H%M%S)"
    TMP_DIR=$(mktemp -d -p /tmp afl_benchmark_XXXXXX)
    RESULTS_DIR="$TMP_DIR/$TEST_ID"
    CREATED_TMP_DIR=true
else
    # Use the provided custom directory
    RESULTS_DIR="$CUSTOM_RESULTS_DIR"
    CREATED_TMP_DIR=false
fi

STATS_DIR="$RESULTS_DIR/stats"

# Create results directory
mkdir -p "$RESULTS_DIR"
mkdir -p "$STATS_DIR/custom"
mkdir -p "$STATS_DIR/EEVDF"

# Cleanup function to remove temporary files
cleanup_tmp() {
    if [ "$CREATED_TMP_DIR" = true ] && [ -d "$TMP_DIR" ]; then
        echo "Cleaning up temporary directory: $TMP_DIR"
        rm -rf "$TMP_DIR"
    fi
}

# Register cleanup function to run on exit
trap cleanup_tmp EXIT

# Save test parameters
if [ -z "$CUSTOM_RESULTS_DIR" ]; then
    echo "Test ID: $TEST_ID" > "$RESULTS_DIR/parameters.txt"
else
    echo "Test ID: Custom directory" > "$RESULTS_DIR/parameters.txt"
fi
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
echo "" >> "$RESULTS_DIR/parameters.txt"
echo "Power schedule distribution:" >> "$RESULTS_DIR/parameters.txt"

# Document the power schedule distribution
for i in $(seq 1 "$NUM_INSTANCES"); do
    POWER_SCHEDULE=$(assign_power_schedule "$i" "$NUM_INSTANCES")
    echo "  Instance $i: $POWER_SCHEDULE" >> "$RESULTS_DIR/parameters.txt"
done

# Function to assign power schedule based on instance number and total count
assign_power_schedule() {
    local instance_num=$1
    local total_instances=$2

    # First instance is always the main node with EXPLORE
    if [ "$instance_num" -eq 1 ]; then
        echo "-p explore"
        return
    fi

    # For the remaining instances, distribute schedules based on percentages
    # Calculate which group this instance falls into
    local exploit_count=$(( total_instances * 30 / 100 ))
    local explore_count=$(( total_instances * 30 / 100 ))
    local fast_count=$(( total_instances * 20 / 100 ))
    local rare_count=$(( total_instances * 10 / 100 ))
    local cmplog_count=$(( total_instances * 10 / 100 ))

    # Ensure at least one instance of each type if we have enough instances
    if [ "$exploit_count" -lt 1 ] && [ "$total_instances" -ge 5 ]; then exploit_count=1; fi
    if [ "$explore_count" -lt 1 ] && [ "$total_instances" -ge 5 ]; then explore_count=1; fi
    if [ "$fast_count" -lt 1 ] && [ "$total_instances" -ge 5 ]; then fast_count=1; fi
    if [ "$rare_count" -lt 1 ] && [ "$total_instances" -ge 5 ]; then rare_count=1; fi
    if [ "$cmplog_count" -lt 1 ] && [ "$total_instances" -ge 5 ]; then cmplog_count=1; fi

    # Calculate the upper bounds for each group
    local exploit_upper=$(( 1 + exploit_count ))
    local explore_upper=$(( exploit_upper + explore_count ))
    local fast_upper=$(( explore_upper + fast_count ))
    local rare_upper=$(( fast_upper + rare_count ))
    local cmplog_upper=$(( rare_upper + cmplog_count ))

    # Assign schedule based on which group the instance falls into
    if [ "$instance_num" -lt "$exploit_upper" ]; then
        echo "-p exploit"
    elif [ "$instance_num" -lt "$explore_upper" ]; then
        echo "-p explore"
    elif [ "$instance_num" -lt "$fast_upper" ]; then
        echo "-p fast"
    elif [ "$instance_num" -lt "$rare_upper" ]; then
        echo "-p rare"
    elif [ "$instance_num" -lt "$cmplog_upper" ] && [ "$total_instances" -ge 5 ]; then
        echo "-l 2AT"  # CMPLOG with transformations
    else
        # For any remaining instances, cycle through the schedules
        case $(( (instance_num - cmplog_upper) % 4 )) in
            0) echo "-p exploit" ;;
            1) echo "-p explore" ;;
            2) echo "-p fast" ;;
            3) echo "-p rare" ;;
        esac
    fi
}

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
            -m "$SLICE_MIN_US" \
            -n "$NUM_INSTANCES" &

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

    # Start stats collector (To generate productivity stats per boost period)
    # /home/ernesto/Documents/AFLplusplus/afl_scheduler/stats_collector "$STATS_DIR/$scheduler" &
    # STATS_PID=$! # if you activate it, add this to the call to compare_results.py: "$STATS_DIR" before redirect >

    # Start AFL++ instances with appropriate power schedules
    for i in $(seq 1 "$NUM_INSTANCES"); do
        if [ "$i" -eq 1 ]; then
            # First instance is the main node
            AFL_MODE="-M"
        else
            # Other instances are secondary nodes
            AFL_MODE="-S"
        fi

        # Assign power schedule based on instance number and total count
        POWER_SCHEDULE=$(assign_power_schedule "$i" "$NUM_INSTANCES")

        # Start AFL++ instance
        sudo AFL_NO_AFFINITY=1 AFL_TMPDIR="$TMP_DIR" /home/ernesto/Documents/AFLplusplus/afl-fuzz -i /home/ernesto/Documents/AFLplusplus/original_seeds -o "$output_dir" \
            $AFL_MODE "fuzzer$i" -t "$TIMEOUT" -m "$MEMORY_LIMIT" $POWER_SCHEDULE \
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
    # kill $STATS_PID

    # If using custom scheduler, stop it
    if [ "$scheduler" = "custom" ]; then
        echo "Stopping enhanced scheduler..."
        sudo killall afl_sched_loader_enhanced_simple
        sleep 2
    fi

    echo "Benchmark with $scheduler scheduler completed"
}

# Run benchmarks based on scheduler order
run_benchmark "custom"

# Generate a simplified report instead of comparison
echo "Generating custom scheduler report..."
# Replace the comparison report generation with a simple stats extraction
python3 /home/ernesto/Documents/AFLplusplus/afl_scheduler/extract_custom_stats.py "$RESULTS_DIR/custom" > "$RESULTS_DIR/custom_report.txt"

echo "Benchmark completed. Results in $RESULTS_DIR/"
echo "Custom report: $RESULTS_DIR/custom_report.txt"

# Copy report to a more accessible location
cp "$RESULTS_DIR/custom_report.txt" "enhanced_simple_benchmark_latest.txt"
echo "Latest report also available at: enhanced_simple_benchmark_latest.txt"

# If a final results directory was specified, copy essential files there
if [ -n "$FINAL_RESULTS_DIR" ]; then
    echo "Copying essential results to final destination: $FINAL_RESULTS_DIR"
    mkdir -p "$FINAL_RESULTS_DIR"
    
    # Copy only essential files
    cp "$RESULTS_DIR/custom_report.txt" "$FINAL_RESULTS_DIR/custom_report.txt"
    cp "$RESULTS_DIR/parameters.txt" "$FINAL_RESULTS_DIR/parameters.txt"
fi
