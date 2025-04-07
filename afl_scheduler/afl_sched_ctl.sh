#!/bin/bash
#
# Control script for AFL++ CPU Scheduler
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

# Check if action is specified
if [ -z "$ACTION" ]; then
  echo "No action specified. Use --help for usage information"
  exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Function to check if a process is running
is_running() {
  local PROCESS_NAME="$1"
  if pgrep -x "$PROCESS_NAME" > /dev/null; then
    return 0  # Running
  else
    return 1  # Not running
  fi
}

# Function to start the scheduler
start_scheduler() {
  echo "Starting AFL++ CPU Scheduler..."
  
  # Check if already running
  if is_running "afl_monitor" || is_running "afl_sched"; then
    echo "AFL++ CPU Scheduler is already running"
    return 1
  fi
  
  # Start monitor daemon
  "$SCRIPT_DIR/afl_monitor" -i "$POLL_INTERVAL" &
  MONITOR_PID=$!
  echo "Started monitor daemon (PID: $MONITOR_PID)"
  
  # Wait a moment for the monitor to initialize
  sleep 1
  
  # Start scheduler
  "$SCRIPT_DIR/afl_sched" &
  SCHED_PID=$!
  echo "Started scheduler (PID: $SCHED_PID)"
  
  # Wait to make sure everything started correctly
  sleep 2
  
  # Check if processes are still running
  if ! is_running "afl_monitor" || ! is_running "afl_sched"; then
    echo "Failed to start AFL++ CPU Scheduler"
    stop_scheduler
    return 1
  fi
  
  echo "AFL++ CPU Scheduler started successfully"
  return 0
}

# Function to stop the scheduler
stop_scheduler() {
  echo "Stopping AFL++ CPU Scheduler..."
  
  # Kill scheduler
  if is_running "afl_sched"; then
    pkill -x "afl_sched"
    echo "Stopped scheduler"
  else
    echo "Scheduler is not running"
  fi
  
  # Kill monitor daemon
  if is_running "afl_monitor"; then
    pkill -x "afl_monitor"
    echo "Stopped monitor daemon"
  else
    echo "Monitor daemon is not running"
  fi
  
  # Clean up shared memory
  SHMID=$(ipcs -m | grep 0x41 | awk '{print $2}')
  if [ -n "$SHMID" ]; then
    ipcrm -m "$SHMID"
    echo "Removed shared memory"
  fi
  
  echo "AFL++ CPU Scheduler stopped"
  return 0
}

# Function to check status
check_status() {
  local MONITOR_RUNNING=0
  local SCHED_RUNNING=0
  
  if is_running "afl_monitor"; then
    MONITOR_RUNNING=1
    MONITOR_PID=$(pgrep -x "afl_monitor")
    echo "Monitor daemon is running (PID: $MONITOR_PID)"
  else
    echo "Monitor daemon is not running"
  fi
  
  if is_running "afl_sched"; then
    SCHED_RUNNING=1
    SCHED_PID=$(pgrep -x "afl_sched")
    echo "Scheduler is running (PID: $SCHED_PID)"
  else
    echo "Scheduler is not running"
  fi
  
  if [ $MONITOR_RUNNING -eq 1 ] && [ $SCHED_RUNNING -eq 1 ]; then
    echo "AFL++ CPU Scheduler is fully operational"
    return 0
  else
    echo "AFL++ CPU Scheduler is not fully operational"
    return 1
  fi
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
