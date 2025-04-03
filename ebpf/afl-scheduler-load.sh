#!/bin/bash
# AFL++ Feedback-Guided CPU Scheduler Loader

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Check if sched_ext module is loaded
if ! lsmod | grep -q sched_ext; then
  echo "Loading sched_ext module..."
  modprobe sched_ext
  if [ $? -ne 0 ]; then
    echo "Failed to load sched_ext module. Make sure your kernel supports sched_ext."
    exit 1
  fi
fi

# Build the scheduler if needed
if [ ! -f afl_scheduler.bpf.o ] || [ ! -f afl_scheduler_daemon ]; then
  echo "Building scheduler components..."
  make
  if [ $? -ne 0 ]; then
    echo "Build failed. Make sure you have the required dependencies installed."
    exit 1
  fi
fi

# Create metrics directory if specified
METRICS_DIR="./scheduler_metrics"
if [ $# -gt 0 ]; then
  METRICS_DIR="$1"
  mkdir -p "$METRICS_DIR"
  echo "Metrics will be saved to $METRICS_DIR"
fi

# Run the scheduler daemon
echo "Starting AFL++ scheduler daemon..."
./afl_scheduler_daemon "$METRICS_DIR"

# The daemon will handle attaching the scheduler and monitoring fuzzer processes
