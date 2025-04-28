#!/bin/bash
#
# Script to run the Gaussian Process-based optimizer for AFL++ scheduler parameters
#

# Check if we have sudo access
if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run with sudo. Please run with: sudo $0"
    exit 1
fi

# Default parameters
TRIALS=30
DURATION=6
INITIAL_SAMPLES=10
REPLICATIONS=2
VISUALIZE_ONLY=false
RESULTS_DIR=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --trials)
      TRIALS="$2"
      shift 2
      ;;
    --duration)
      DURATION="$2"
      shift 2
      ;;
    --initial-samples)
      INITIAL_SAMPLES="$2"
      shift 2
      ;;
    --replications)
      REPLICATIONS="$2"
      shift 2
      ;;
    --visualize-only)
      VISUALIZE_ONLY=true
      shift
      ;;
    --results-dir)
      RESULTS_DIR="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: sudo $0 [options]"
      echo ""
      echo "Options:"
      echo "  --trials N             Number of trials to run (default: $TRIALS)"
      echo "  --duration N           Duration of each benchmark in minutes (default: $DURATION)"
      echo "  --initial-samples N    Number of initial random samples (default: $INITIAL_SAMPLES)"
      echo "  --replications N       Number of replications for each parameter combination (default: $REPLICATIONS)"
      echo "  --visualize-only       Only generate visualizations for existing results"
      echo "  --results-dir DIR      Specify a results directory to visualize (for --visualize-only)"
      echo "  -h, --help             Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Make sure the script is executable
chmod +x ./afl_scheduler/gp_optimizer.py

# Run the optimizer
if [ "$VISUALIZE_ONLY" = true ]; then
  # Only generate visualizations
  if [ -n "$RESULTS_DIR" ]; then
    python3 ./afl_scheduler/gp_optimizer.py --visualize-only --results-dir "$RESULTS_DIR"
  else
    python3 ./afl_scheduler/gp_optimizer.py --visualize-only
  fi
else
  # Run the full optimization
  python3 ./afl_scheduler/gp_optimizer.py \
    --trials "$TRIALS" \
    --duration "$DURATION" \
    --initial-samples "$INITIAL_SAMPLES" \
    --replications "$REPLICATIONS"
fi

echo "Optimization completed. Check the gp_optimization_results_* directory for results."
