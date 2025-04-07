#!/bin/bash
#
# Test script for AFL++ CPU Scheduler
#
# This script creates a simple test environment with multiple AFL++ instances
# and verifies that the scheduler is working correctly.
#

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Configuration
AFL_PATH=$(which afl-fuzz)
if [ -z "$AFL_PATH" ]; then
  echo "AFL++ not found. Please install AFL++ and make sure it's in your PATH."
  exit 1
fi

TEST_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PARENT_DIR="$(dirname "$TEST_DIR")"
TARGET_DIR="$TEST_DIR/target"
INPUT_DIR="$TEST_DIR/input"
OUTPUT_DIR="$TEST_DIR/output"

# Create test directories
mkdir -p "$TARGET_DIR" "$INPUT_DIR" "$OUTPUT_DIR"

# Create a simple test program
cat > "$TARGET_DIR/test_program.c" << EOF
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    char buffer[100];
    
    if (argc < 2) {
        printf("Usage: %s <input_file>\n", argv[0]);
        return 1;
    }
    
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        perror("Failed to open input file");
        return 1;
    }
    
    size_t bytes_read = fread(buffer, 1, sizeof(buffer) - 1, f);
    buffer[bytes_read] = '\0';
    fclose(f);
    
    // Simple crash condition
    if (bytes_read >= 3 && buffer[0] == 'C' && buffer[1] == 'R' && buffer[2] == 'A') {
        abort();
    }
    
    // Different paths based on input
    if (bytes_read >= 2) {
        if (buffer[0] == 'A') {
            printf("Path A\n");
            if (buffer[1] == '1') {
                printf("Path A1\n");
            } else if (buffer[1] == '2') {
                printf("Path A2\n");
            }
        } else if (buffer[0] == 'B') {
            printf("Path B\n");
            if (buffer[1] == '1') {
                printf("Path B1\n");
            } else if (buffer[1] == '2') {
                printf("Path B2\n");
            }
        }
    }
    
    return 0;
}
EOF

# Compile the test program
gcc -g -o "$TARGET_DIR/test_program" "$TARGET_DIR/test_program.c"

# Create initial test cases
echo "A1" > "$INPUT_DIR/test1"
echo "B1" > "$INPUT_DIR/test2"

# Function to start AFL++ instances
start_afl_instances() {
    local NUM_INSTANCES=$1
    
    echo "Starting $NUM_INSTANCES AFL++ instances..."
    
    for i in $(seq 1 $NUM_INSTANCES); do
        "$AFL_PATH" -i "$INPUT_DIR" -o "$OUTPUT_DIR" -S "fuzzer$i" \
            -d "$TARGET_DIR/test_program" @@ &
        echo "Started fuzzer$i (PID: $!)"
    done
    
    echo "All AFL++ instances started"
}

# Function to stop AFL++ instances
stop_afl_instances() {
    echo "Stopping AFL++ instances..."
    pkill -f "afl-fuzz.*test_program"
    echo "All AFL++ instances stopped"
}

# Function to start the scheduler
start_scheduler() {
    echo "Starting AFL++ CPU Scheduler..."
    "$PARENT_DIR/afl_sched_ctl.sh" start
}

# Function to stop the scheduler
stop_scheduler() {
    echo "Stopping AFL++ CPU Scheduler..."
    "$PARENT_DIR/afl_sched_ctl.sh" stop
}

# Function to clean up
cleanup() {
    stop_afl_instances
    stop_scheduler
    echo "Cleaning up test environment..."
    rm -rf "$TARGET_DIR" "$INPUT_DIR" "$OUTPUT_DIR"
    echo "Cleanup complete"
}

# Register cleanup function
trap cleanup EXIT

# Main test sequence
echo "=== AFL++ CPU Scheduler Test ==="
echo ""

# Start the scheduler
start_scheduler

# Start AFL++ instances
start_afl_instances 4

echo ""
echo "Test environment is running."
echo "The scheduler should now be prioritizing AFL++ instances based on their performance."
echo ""
echo "To verify that the scheduler is working:"
echo "1. Monitor CPU usage: watch -n 1 'ps -eo pid,pcpu,comm | grep afl-fuzz'"
echo "2. Check fuzzer stats: cat $OUTPUT_DIR/fuzzer*/fuzzer_stats"
echo "3. Inject a 'productive' test case to see priority boost:"
echo "   echo 'CRA' > $OUTPUT_DIR/fuzzer1/queue/manual_case"
echo ""
echo "Press Ctrl+C to stop the test and clean up."

# Wait for user to press Ctrl+C
while true; do
    sleep 1
done
