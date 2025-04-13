#!/bin/bash
#
# Control script for AFL++ CPU Scheduler (Direct BPF Map Access)
#

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Default values
POLL_INTERVAL=1000

# Parse arguments
ACTION=""
while [[ $# -gt 0 ]]; do
  case $1 in
    start|stop|status)
      ACTION="$1"
      shift
      ;;
    -i|--interval)
      POLL_INTERVAL="$2"
      shift 2
      ;;
    -h|--help)
      echo "Usage: $0 [start|stop|status] [-i poll_interval]"
      echo ""
      echo "Commands:"
      echo "  start       Start the AFL++ CPU Scheduler"
      echo "  stop        Stop the AFL++ CPU Scheduler"
      echo "  status      Check the status of the AFL++ CPU Scheduler"
      echo ""
      echo "Options:"
      echo "  -i, --interval INTERVAL  Set polling interval in milliseconds (default: 1000)"
      echo "  -h, --help               Show this help message"
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
  echo "Starting AFL++ CPU Scheduler..."
  
  # Check if already running
  if is_running "afl_monitor_direct" || is_running "afl_sched_loader"; then
    echo "AFL++ CPU Scheduler is already running"
    return 1
  fi
  
  # Start BPF loader
  "$SCRIPT_DIR/afl_sched_loader" &
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
  "$SCRIPT_DIR/afl_monitor_direct" -i "$POLL_INTERVAL" &
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
  if is_running "afl_monitor_direct"; then
    pkill -x "afl_monitor_direct"
    echo "Stopped monitor daemon"
  else
    echo "Monitor daemon is not running"
  fi
  
  # Kill BPF loader
  if is_running "afl_sched_loader"; then
    pkill -x "afl_sched_loader"
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
  
  if is_running "afl_sched_loader"; then
    echo "BPF loader: Running"
    LOADER_PID=$(pgrep -x "afl_sched_loader")
    echo "  PID: $LOADER_PID"
  else
    echo "BPF loader: Not running"
  fi
  
  if is_running "afl_monitor_direct"; then
    echo "Monitor daemon: Running"
    MONITOR_PID=$(pgrep -x "afl_monitor_direct")
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
