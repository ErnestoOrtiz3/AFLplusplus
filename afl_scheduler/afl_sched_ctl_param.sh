#!/bin/bash
#
# Control script for AFL++ CPU Scheduler with Configurable Parameters
#

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Default parameter values
POLL_INTERVAL=1000
REBALANCE_INTERVAL=300
NEW_PATH_SCORE=100
NEW_CRASH_SCORE=500
SCORE_DECAY_FACTOR=0.99
WEIGHT_SCALE_FACTOR=10
MIN_WEIGHT_PERCENT=10
BOOST_WEIGHT=1000
BOOST_DURATION=1000000
SLICE_US=20000
SLICE_MIN_US=5000

# Parse arguments
ACTION=""
while [[ $# -gt 0 ]]; do
  case $1 in
    start|stop|status)
      ACTION="$1"
      shift
      ;;
    -i|--poll-interval)
      POLL_INTERVAL="$2"
      shift 2
      ;;
    -r|--rebalance-interval)
      REBALANCE_INTERVAL="$2"
      shift 2
      ;;
    -p|--path-score)
      NEW_PATH_SCORE="$2"
      shift 2
      ;;
    -c|--crash-score)
      NEW_CRASH_SCORE="$2"
      shift 2
      ;;
    -d|--decay-factor)
      SCORE_DECAY_FACTOR="$2"
      shift 2
      ;;
    -w|--weight-scale)
      WEIGHT_SCALE_FACTOR="$2"
      shift 2
      ;;
    -m|--min-weight)
      MIN_WEIGHT_PERCENT="$2"
      shift 2
      ;;
    -b|--boost-weight)
      BOOST_WEIGHT="$2"
      shift 2
      ;;
    -t|--boost-duration)
      BOOST_DURATION="$2"
      shift 2
      ;;
    -s|--slice)
      SLICE_US="$2"
      shift 2
      ;;
    -n|--min-slice)
      SLICE_MIN_US="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [start|stop|status] [options]"
      echo ""
      echo "Commands:"
      echo "  start       Start the AFL++ CPU Scheduler"
      echo "  stop        Stop the AFL++ CPU Scheduler"
      echo "  status      Check the status of the AFL++ CPU Scheduler"
      echo ""
      echo "Options:"
      echo "  -i, --poll-interval INTERVAL    Polling interval in milliseconds (default: 1000)"
      echo "  -r, --rebalance-interval SEC    Rebalance interval in seconds (default: 300)"
      echo "  -p, --path-score SCORE          Score for finding a new path (default: 100)"
      echo "  -c, --crash-score SCORE         Score for finding a new crash (default: 500)"
      echo "  -d, --decay-factor FACTOR       Score decay factor (default: 0.99)"
      echo "  -w, --weight-scale FACTOR       Weight scale factor (default: 10)"
      echo "  -m, --min-weight PERCENT        Minimum weight percentage (default: 10)"
      echo "  -b, --boost-weight WEIGHT       Boost weight (default: 1000)"
      echo "  -t, --boost-duration DURATION   Boost duration in microseconds (default: 1000000)"
      echo "  -s, --slice MICROSECONDS        Time slice in microseconds (default: 20000)"
      echo "  -n, --min-slice MICROSECONDS    Minimum time slice in microseconds (default: 5000)"
      echo "  -h, --help                      Show this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Use --help for usage information"
      exit 1
      ;;
  esac
done

# Set default action if none specified
if [ -z "$ACTION" ]; then
  echo "No action specified. Use --help for usage information."
  exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to check if a process is running
is_running() {
  pgrep -x "$1" >/dev/null
  return $?
}

# Function to start the scheduler
start_scheduler() {
  echo "Starting AFL++ CPU Scheduler with the following parameters:"
  echo "  Poll interval: $POLL_INTERVAL ms"
  echo "  Rebalance interval: $REBALANCE_INTERVAL sec"
  echo "  New path score: $NEW_PATH_SCORE"
  echo "  New crash score: $NEW_CRASH_SCORE"
  echo "  Score decay factor: $SCORE_DECAY_FACTOR"
  echo "  Weight scale factor: $WEIGHT_SCALE_FACTOR"
  echo "  Minimum weight percent: $MIN_WEIGHT_PERCENT%"
  echo "  Boost weight: $BOOST_WEIGHT"
  echo "  Boost duration: $BOOST_DURATION us"
  echo "  Time slice: $SLICE_US us"
  echo "  Minimum time slice: $SLICE_MIN_US us"
  
  # Check if already running
  if is_running "afl_monitor_param" || is_running "afl_sched_loader_param"; then
    echo "AFL++ CPU Scheduler is already running"
    return 1
  fi
  
  # Start BPF loader
  "$SCRIPT_DIR/afl_sched_loader_param" -b "$BOOST_DURATION" -s "$SLICE_US" -m "$SLICE_MIN_US" &
  LOADER_PID=$!
  echo "Started BPF loader (PID: $LOADER_PID)"
  
  # Wait a moment for the loader to initialize
  sleep 2
  
  # Check if loader is still running
  if ! ps -p $LOADER_PID > /dev/null; then
    echo "Failed to start BPF loader"
    return 1
  fi
  
  # Start monitor daemon
  "$SCRIPT_DIR/afl_monitor_param" \
    -i "$POLL_INTERVAL" \
    -r "$REBALANCE_INTERVAL" \
    -p "$NEW_PATH_SCORE" \
    -c "$NEW_CRASH_SCORE" \
    -d "$SCORE_DECAY_FACTOR" \
    -w "$WEIGHT_SCALE_FACTOR" \
    -m "$MIN_WEIGHT_PERCENT" \
    -b "$BOOST_WEIGHT" \
    -t "$BOOST_DURATION" &
  MONITOR_PID=$!
  echo "Started monitor daemon (PID: $MONITOR_PID)"
  
  # Wait to make sure everything started correctly
  sleep 1
  
  # Check if monitor is still running
  if ! ps -p $MONITOR_PID > /dev/null; then
    echo "Failed to start monitor daemon"
    kill $LOADER_PID 2>/dev/null
    return 1
  fi
  
  echo "AFL++ CPU Scheduler started successfully"
  return 0
}

# Function to stop the scheduler
stop_scheduler() {
  echo "Stopping AFL++ CPU Scheduler..."
  
  # Kill monitor daemon
  if is_running "afl_monitor_param"; then
    pkill -x "afl_monitor_param"
    echo "Stopped monitor daemon"
  else
    echo "Monitor daemon is not running"
  fi
  
  # Kill BPF loader
  if is_running "afl_sched_loader_param"; then
    pkill -x "afl_sched_loader_param"
    echo "Stopped BPF loader"
  else
    echo "BPF loader is not running"
  fi
  
  echo "AFL++ CPU Scheduler stopped"
  return 0
}

# Function to check scheduler status
check_status() {
  echo "AFL++ CPU Scheduler status:"
  
  if is_running "afl_sched_loader_param"; then
    echo "BPF loader: Running"
    LOADER_PID=$(pgrep -x "afl_sched_loader_param")
    echo "  PID: $LOADER_PID"
  else
    echo "BPF loader: Not running"
  fi
  
  if is_running "afl_monitor_param"; then
    echo "Monitor daemon: Running"
    MONITOR_PID=$(pgrep -x "afl_monitor_param")
    echo "  PID: $MONITOR_PID"
  else
    echo "Monitor daemon: Not running"
  fi
  
  # Check if BPF maps exist
  if [ -e "/sys/fs/bpf/afl_scheduler/afl_weights" ]; then
    echo "BPF maps: Available"
  else
    echo "BPF maps: Not available"
  fi
  
  return 0
}

# Execute the requested action
case "$ACTION" in
  start)
    start_scheduler
    ;;
  stop)
    stop_scheduler
    ;;
  status)
    check_status
    ;;
esac

exit $?
