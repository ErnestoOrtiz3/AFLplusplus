#!/bin/bash
# Test script for the AFL++ scheduler feedback mechanism only
# This script doesn't require the eBPF scheduler to be available

# Default settings
DURATION=300  # 5 minutes by default
OUTPUT_DIR="./output_feedback"
METRICS_DIR="./metrics_feedback"

# Parse command line arguments
while getopts "d:o:m:" opt; do
    case $opt in
        d) DURATION="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        m) METRICS_DIR="$OPTARG" ;;
        *) echo "Usage: $0 [-d DURATION] [-o OUTPUT_DIR] [-m METRICS_DIR]"; exit 1 ;;
    esac
done

# Create output directories
mkdir -p "$OUTPUT_DIR" "$METRICS_DIR"

# Compile the target
echo "Compiling target..."
make

if [ $? -ne 0 ]; then
    echo "Compilation failed!"
    exit 1
fi

# Set path to AFL++ binaries
AFL_PATH="$(cd .. && pwd)"
echo "Using AFL++ binaries from: $AFL_PATH"

# Start fuzzing with scheduler feedback
echo "Starting fuzzing with scheduler feedback..."
AFL_SKIP_CPUFREQ=1 $AFL_PATH/afl-fuzz -i input -o "$OUTPUT_DIR" -M main -D -V "$DURATION" -- ./scheduler_test &
FUZZER1_PID=$!

# Start a second fuzzer with scheduler feedback
echo "Starting second fuzzer with scheduler feedback..."
AFL_SKIP_CPUFREQ=1 $AFL_PATH/afl-fuzz -i input -o "$OUTPUT_DIR" -S scheduler -D -V "$DURATION" -- ./scheduler_test &
FUZZER2_PID=$!

# Start a third fuzzer without scheduler feedback
echo "Starting third fuzzer without scheduler feedback..."
AFL_SKIP_CPUFREQ=1 $AFL_PATH/afl-fuzz -i input -o "$OUTPUT_DIR" -S regular -D -V "$DURATION" -- ./scheduler_test &
FUZZER3_PID=$!

# Monitor the shared memory
echo "Monitoring scheduler feedback shared memory..."
rm -rf "$METRICS_DIR"/*
mkdir -p "$METRICS_DIR"
echo "Looking for scheduler feedback in $OUTPUT_DIR/scheduler/"
(
    while kill -0 $FUZZER2_PID 2>/dev/null; do
        # Check if the scheduler feedback file exists
        FEEDBACK_FILE="$OUTPUT_DIR/scheduler/scheduler_feedback.txt"
        if [ -f "$FEEDBACK_FILE" ]; then
            SHM_ID=$(cat "$FEEDBACK_FILE")
            echo "Found scheduler feedback SHM ID: $SHM_ID"
            echo "SHM_ID=$SHM_ID" > "$METRICS_DIR/shm_id.txt"

            # Create a simple monitoring script
            cat > "$METRICS_DIR/monitor.c" << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <time.h>

typedef struct scheduler_feedback {
    pid_t pid;                  /* Process ID of this fuzzer */
    unsigned long long last_update_time;     /* Timestamp of last update (ms) */
    unsigned int new_edges_found;      /* New edges found since last update */
    unsigned int total_edges_found;    /* Total edges found by this fuzzer */
    unsigned int execs_per_sec;        /* Current execution speed */
    unsigned int paths_found;          /* Total paths discovered */
    unsigned int unique_crashes;       /* Number of unique crashes found */
    unsigned int unique_hangs;         /* Number of unique hangs found */
    unsigned int queue_cycle;          /* Current queue cycle */
    unsigned int pending_favs;         /* Number of pending favored paths */
    unsigned char performance_score;    /* Calculated performance score (0-100) */
    unsigned char reserved[3];          /* Padding for alignment */
} scheduler_feedback_t;

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <shm_id> [interval_seconds]\n", argv[0]);
        return 1;
    }

    int shm_id = atoi(argv[1]);
    int interval = (argc > 2) ? atoi(argv[2]) : 5;  // Default 5 seconds

    // Attach to shared memory
    scheduler_feedback_t *feedback = (scheduler_feedback_t *)shmat(shm_id, NULL, SHM_RDONLY);
    if (feedback == (void *)-1) {
        perror("Failed to attach to shared memory");
        return 1;
    }

    // Create CSV file
    FILE *csv = fopen("feedback_metrics.csv", "w");
    if (!csv) {
        perror("Failed to create CSV file");
        shmdt(feedback);
        return 1;
    }

    // Write CSV header
    fprintf(csv, "timestamp,pid,total_edges,new_edges,execs_per_sec,paths,crashes,hangs,queue_cycle,pending_favs,score\n");

    // Monitor loop
    while (1) {
        time_t now = time(NULL);
        char timestamp[64];
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

        // Print current metrics
        printf("\n=== Scheduler Feedback Metrics (%s) ===\n", timestamp);
        printf("PID: %d\n", feedback->pid);
        printf("Last update: %llu ms ago\n", get_current_time_ms() - feedback->last_update_time);
        printf("Total edges found: %u\n", feedback->total_edges_found);
        printf("New edges found: %u\n", feedback->new_edges_found);
        printf("Executions per second: %u\n", feedback->execs_per_sec);
        printf("Paths found: %u\n", feedback->paths_found);
        printf("Unique crashes: %u\n", feedback->unique_crashes);
        printf("Unique hangs: %u\n", feedback->unique_hangs);
        printf("Queue cycle: %u\n", feedback->queue_cycle);
        printf("Pending favored: %u\n", feedback->pending_favs);
        printf("Performance score: %u\n", feedback->performance_score);

        // Write to CSV
        fprintf(csv, "%s,%d,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
                timestamp, feedback->pid, feedback->total_edges_found,
                feedback->new_edges_found, feedback->execs_per_sec,
                feedback->paths_found, feedback->unique_crashes,
                feedback->unique_hangs, feedback->queue_cycle,
                feedback->pending_favs, feedback->performance_score);
        fflush(csv);

        sleep(interval);
    }

    // Clean up
    fclose(csv);
    shmdt(feedback);
    return 0;
}

unsigned long long get_current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned long long)(tv.tv_sec) * 1000 + (unsigned long long)(tv.tv_usec) / 1000;
}
EOF

            # Compile and run the monitoring script
            gcc -o "$METRICS_DIR/monitor" "$METRICS_DIR/monitor.c"
            cd "$METRICS_DIR"
            ./monitor "$SHM_ID" 2 > monitor_output.txt &
            MONITOR_PID=$!

            # Exit the loop once we've found and started monitoring
            break
        fi

        sleep 2
    done
) &
MONITOR_SCRIPT_PID=$!

# Wait for fuzzing to complete
wait $FUZZER1_PID
wait $FUZZER2_PID
wait $FUZZER3_PID

# Kill the monitor script if it's still running
kill $MONITOR_SCRIPT_PID 2>/dev/null
kill $(pgrep -f "$METRICS_DIR/monitor") 2>/dev/null

# Generate a simple report
echo "Test completed!"
echo "Results are available in $OUTPUT_DIR"
echo "Metrics are available in $METRICS_DIR"

# Compare results
echo "Comparing results..."
MAIN_PATHS=$(grep "paths_total" "$OUTPUT_DIR/main/fuzzer_stats" | awk '{print $3}')
SCHEDULER_PATHS=$(grep "paths_total" "$OUTPUT_DIR/scheduler/fuzzer_stats" | awk '{print $3}')
REGULAR_PATHS=$(grep "paths_total" "$OUTPUT_DIR/regular/fuzzer_stats" | awk '{print $3}')

MAIN_EXECS=$(grep "execs_done" "$OUTPUT_DIR/main/fuzzer_stats" | awk '{print $3}')
SCHEDULER_EXECS=$(grep "execs_done" "$OUTPUT_DIR/scheduler/fuzzer_stats" | awk '{print $3}')
REGULAR_EXECS=$(grep "execs_done" "$OUTPUT_DIR/regular/fuzzer_stats" | awk '{print $3}')

echo "Main instance:"
echo "  Paths found: $MAIN_PATHS"
echo "  Executions: $MAIN_EXECS"
echo "Scheduler feedback instance:"
echo "  Paths found: $SCHEDULER_PATHS"
echo "  Executions: $SCHEDULER_EXECS"
echo "Regular instance:"
echo "  Paths found: $REGULAR_PATHS"
echo "  Executions: $REGULAR_EXECS"

# Create a simple visualization of the metrics
if [ -f "$METRICS_DIR/feedback_metrics.csv" ]; then
    echo "Creating visualizations..."

    # Create a simple Python script for visualization
    cat > "$METRICS_DIR/visualize.py" << EOF
#!/usr/bin/env python3
import pandas as pd
import matplotlib.pyplot as plt
import sys
from datetime import datetime

# Read the CSV file
df = pd.read_csv('feedback_metrics.csv')

# Convert timestamp to datetime
df['timestamp'] = pd.to_datetime(df['timestamp'])

# Create plots directory
import os
os.makedirs('plots', exist_ok=True)

# Plot total edges over time
plt.figure(figsize=(10, 6))
plt.plot(df['timestamp'], df['total_edges'], marker='o')
plt.title('Total Edges Found Over Time')
plt.xlabel('Time')
plt.ylabel('Total Edges')
plt.grid(True)
plt.savefig('plots/total_edges.png')
plt.close()

# Plot new edges over time
plt.figure(figsize=(10, 6))
plt.plot(df['timestamp'], df['new_edges'], marker='o', color='green')
plt.title('New Edges Found Over Time')
plt.xlabel('Time')
plt.ylabel('New Edges')
plt.grid(True)
plt.savefig('plots/new_edges.png')
plt.close()

# Plot executions per second over time
plt.figure(figsize=(10, 6))
plt.plot(df['timestamp'], df['execs_per_sec'], marker='o', color='orange')
plt.title('Executions Per Second Over Time')
plt.xlabel('Time')
plt.ylabel('Execs/Sec')
plt.grid(True)
plt.savefig('plots/execs_per_sec.png')
plt.close()

# Plot performance score over time
plt.figure(figsize=(10, 6))
plt.plot(df['timestamp'], df['score'], marker='o', color='red')
plt.title('Performance Score Over Time')
plt.xlabel('Time')
plt.ylabel('Score')
plt.grid(True)
plt.savefig('plots/performance_score.png')
plt.close()

# Plot paths found over time
plt.figure(figsize=(10, 6))
plt.plot(df['timestamp'], df['paths'], marker='o', color='purple')
plt.title('Paths Found Over Time')
plt.xlabel('Time')
plt.ylabel('Paths')
plt.grid(True)
plt.savefig('plots/paths.png')
plt.close()

print("Visualizations created in plots/ directory")
EOF

    # Make the script executable
    chmod +x "$METRICS_DIR/visualize.py"

    # Run the visualization script
    cd "$METRICS_DIR"
    python3 visualize.py

    echo "Visualizations created in $METRICS_DIR/plots/"
fi
