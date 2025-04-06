#!/bin/bash
# AFL++ Feedback-Guided CPU Scheduler Loader

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Check if sched_ext is available
if [ ! -d "/sys/kernel/sched_ext" ]; then
  echo "Checking if sched_ext module needs to be loaded..."
  if ! lsmod | grep -q sched_ext; then
    echo "Trying to load sched_ext module..."
    modprobe sched_ext 2>/dev/null
    if [ $? -ne 0 ]; then
      echo "Failed to load sched_ext module. Make sure your kernel supports sched_ext."
      echo "Continuing anyway, but the scheduler may not work properly."
    fi
  fi
fi

# Build the scheduler if needed
if [ ! -f afl_scheduler ]; then
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

# Run the scheduler
echo "Starting AFL++ scheduler..."
./afl_scheduler "$METRICS_DIR"

# The scheduler will handle attaching to the sched_ext framework and monitoring fuzzer processes
