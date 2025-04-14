#!/bin/bash
#
# Script to test the parameterized AFL++ CPU Scheduler with different parameters
#

# Default parameters
DURATION=20
NUM_INSTANCES=4
TARGET_PROGRAM="./complex_target_afl"
TARGET_ARGS="@@"
MEMORY_LIMIT="none"
TIMEOUT="7500+"
SCHEDULER_ORDER="custom_first"  # Run custom scheduler first, then CFS

# Default scheduler parameters
BOOST_DURATION=3000000  # 3 seconds in microseconds
BOOST_WEIGHT=3000       # 3x the default
POLL_INTERVAL=1500      # 1.5 seconds
WEIGHT_SCALE=20         # 2x the default
DECAY_FACTOR=0.95       # Slower decay

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
    --poll-interval)
      POLL_INTERVAL="$2"
      shift 2
      ;;
    --weight-scale)
      WEIGHT_SCALE="$2"
      shift 2
      ;;
    --decay-factor)
      DECAY_FACTOR="$2"
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
      echo "  --poll-interval INTERVAL     Poll interval in milliseconds (default: $POLL_INTERVAL)"
      echo "  --weight-scale FACTOR        Weight scale factor (default: $WEIGHT_SCALE)"
      echo "  --decay-factor FACTOR        Score decay factor (default: $DECAY_FACTOR)"
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
TEST_ID="test_$(date +%Y%m%d_%H%M%S)_d${BOOST_DURATION}_w${BOOST_WEIGHT}_p${POLL_INTERVAL}_s${WEIGHT_SCALE}_f${DECAY_FACTOR}"
RESULTS_DIR="param_test_results/${TEST_ID}"

# Create results directory
mkdir -p "$RESULTS_DIR"

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
echo "Poll interval: $POLL_INTERVAL ms" >> "$RESULTS_DIR/parameters.txt"
echo "Weight scale factor: $WEIGHT_SCALE" >> "$RESULTS_DIR/parameters.txt"
echo "Decay factor: $DECAY_FACTOR" >> "$RESULTS_DIR/parameters.txt"

# Function to run the benchmark with a specific scheduler
run_benchmark() {
  local scheduler="$1"
  
  echo "=== Running benchmark with $scheduler scheduler ==="
  
  if [ "$scheduler" = "custom" ]; then
    # Start the parameterized scheduler
    echo "Starting parameterized scheduler with:"
    echo "  Boost duration: $BOOST_DURATION us"
    echo "  Boost weight: $BOOST_WEIGHT"
    echo "  Poll interval: $POLL_INTERVAL ms"
    echo "  Weight scale factor: $WEIGHT_SCALE"
    echo "  Decay factor: $DECAY_FACTOR"
    
    sudo ./afl_scheduler/afl_sched_ctl_param.sh start \
      --boost-duration "$BOOST_DURATION" \
      --boost-weight "$BOOST_WEIGHT" \
      --poll-interval "$POLL_INTERVAL" \
      --weight-scale "$WEIGHT_SCALE" \
      --decay-factor "$DECAY_FACTOR"
    
    # Wait for scheduler to initialize
    sleep 5
    
    # Check if scheduler is running
    if ! sudo ./afl_scheduler/afl_sched_ctl_param.sh status | grep -q "BPF loader: Running"; then
      echo "Error: Failed to start parameterized scheduler"
      return 1
    fi
  fi
  
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
  
  # Run the benchmark
  echo "Running benchmark with $scheduler scheduler..."
  
  # Create a temporary directory for AFL++ output
  TMP_DIR=$(mktemp -d)
  
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
    sudo AFL_NO_AFFINITY=1 ./afl-fuzz -i original_seeds -o "$TMP_DIR" \
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
  
  # Collect results
  echo "Collecting results..."
  
  # Create a directory for this scheduler's results
  mkdir -p "$RESULTS_DIR/$scheduler"
  
  # Copy AFL++ output
  cp -r "$TMP_DIR"/* "$RESULTS_DIR/$scheduler/"
  
  # Clean up temporary directory
  rm -rf "$TMP_DIR"
  
  # If using custom scheduler, stop it
  if [ "$scheduler" = "custom" ]; then
    echo "Stopping parameterized scheduler..."
    sudo ./afl_scheduler/afl_sched_ctl_param.sh stop
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

# Create a simple comparison report
echo "=== Parameterized Scheduler Test Results ===" > "$RESULTS_DIR/comparison.txt"
echo "Test ID: $TEST_ID" >> "$RESULTS_DIR/comparison.txt"
echo "" >> "$RESULTS_DIR/comparison.txt"
echo "Parameters:" >> "$RESULTS_DIR/comparison.txt"
echo "  Boost duration: $BOOST_DURATION us" >> "$RESULTS_DIR/comparison.txt"
echo "  Boost weight: $BOOST_WEIGHT" >> "$RESULTS_DIR/comparison.txt"
echo "  Poll interval: $POLL_INTERVAL ms" >> "$RESULTS_DIR/comparison.txt"
echo "  Weight scale factor: $WEIGHT_SCALE" >> "$RESULTS_DIR/comparison.txt"
echo "  Decay factor: $DECAY_FACTOR" >> "$RESULTS_DIR/comparison.txt"
echo "" >> "$RESULTS_DIR/comparison.txt"

# Compare total executions
CUSTOM_EXECS=0
CFS_EXECS=0

for i in $(seq 1 "$NUM_INSTANCES"); do
  if [ -f "$RESULTS_DIR/custom/fuzzer$i/fuzzer_stats" ]; then
    EXECS=$(grep "execs_done" "$RESULTS_DIR/custom/fuzzer$i/fuzzer_stats" | cut -d ':' -f 2 | tr -d ' ')
    CUSTOM_EXECS=$((CUSTOM_EXECS + EXECS))
  fi
  
  if [ -f "$RESULTS_DIR/cfs/fuzzer$i/fuzzer_stats" ]; then
    EXECS=$(grep "execs_done" "$RESULTS_DIR/cfs/fuzzer$i/fuzzer_stats" | cut -d ':' -f 2 | tr -d ' ')
    CFS_EXECS=$((CFS_EXECS + EXECS))
  fi
done

# Compare paths found
CUSTOM_PATHS=0
CFS_PATHS=0

for i in $(seq 1 "$NUM_INSTANCES"); do
  if [ -d "$RESULTS_DIR/custom/fuzzer$i/queue" ]; then
    PATHS=$(find "$RESULTS_DIR/custom/fuzzer$i/queue" -type f | wc -l)
    CUSTOM_PATHS=$((CUSTOM_PATHS + PATHS))
  fi
  
  if [ -d "$RESULTS_DIR/cfs/fuzzer$i/queue" ]; then
    PATHS=$(find "$RESULTS_DIR/cfs/fuzzer$i/queue" -type f | wc -l)
    CFS_PATHS=$((CFS_PATHS + PATHS))
  fi
done

# Compare crashes found
CUSTOM_CRASHES=0
CFS_CRASHES=0

for i in $(seq 1 "$NUM_INSTANCES"); do
  if [ -d "$RESULTS_DIR/custom/fuzzer$i/crashes" ]; then
    CRASHES=$(find "$RESULTS_DIR/custom/fuzzer$i/crashes" -type f -not -name "README.txt" | wc -l)
    CUSTOM_CRASHES=$((CUSTOM_CRASHES + CRASHES))
  fi
  
  if [ -d "$RESULTS_DIR/cfs/fuzzer$i/crashes" ]; then
    CRASHES=$(find "$RESULTS_DIR/cfs/fuzzer$i/crashes" -type f -not -name "README.txt" | wc -l)
    CFS_CRASHES=$((CFS_CRASHES + CRASHES))
  fi
done

# Calculate differences
EXECS_DIFF=$(echo "scale=2; ($CUSTOM_EXECS - $CFS_EXECS) * 100 / $CFS_EXECS" | bc)
PATHS_DIFF=$(echo "scale=2; ($CUSTOM_PATHS - $CFS_PATHS) * 100 / $CFS_PATHS" | bc)
CRASHES_DIFF=$(echo "scale=2; ($CUSTOM_CRASHES - $CFS_CRASHES) * 100 / $CFS_CRASHES" | bc 2>/dev/null || echo "N/A")

# Write comparison to file
echo "Results:" >> "$RESULTS_DIR/comparison.txt"
echo "  Total executions: Custom=$CUSTOM_EXECS, CFS=$CFS_EXECS, Diff=${EXECS_DIFF}%" >> "$RESULTS_DIR/comparison.txt"
echo "  Total paths found: Custom=$CUSTOM_PATHS, CFS=$CFS_PATHS, Diff=${PATHS_DIFF}%" >> "$RESULTS_DIR/comparison.txt"
echo "  Total crashes found: Custom=$CUSTOM_CRASHES, CFS=$CFS_CRASHES, Diff=${CRASHES_DIFF}%" >> "$RESULTS_DIR/comparison.txt"

echo "Test completed. Results in $RESULTS_DIR/"
echo "Comparison report: $RESULTS_DIR/comparison.txt"
