#!/bin/bash
# Script to collect metrics from multiple AFL++ instances

# Default settings
INTERVAL=5  # Collect metrics every 5 seconds
OUTPUT_DIR="./metrics_multi"
FUZZER_DIR="./output_multi"
DURATION=600  # 10 minutes by default
NUM_INSTANCES=4  # Number of AFL++ instances

# Parse command line arguments
while getopts "i:o:f:d:n:" opt; do
    case $opt in
        i) INTERVAL="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        f) FUZZER_DIR="$OPTARG" ;;
        d) DURATION="$OPTARG" ;;
        n) NUM_INSTANCES="$OPTARG" ;;
        *) echo "Usage: $0 [-i INTERVAL] [-o OUTPUT_DIR] [-f FUZZER_DIR] [-d DURATION] [-n NUM_INSTANCES]"; exit 1 ;;
    esac
done

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Initialize metrics log file
METRICS_LOG="$OUTPUT_DIR/metrics_log.csv"
echo "timestamp,instance,execs_per_sec,paths_total,unique_crashes,unique_hangs,bitmap_cvg,last_find,nice_value,pending_favs,cycles_done,scheduler_local,scheduler_global" > "$METRICS_LOG"

# Initialize aggregate metrics log file
AGGREGATE_LOG="$OUTPUT_DIR/aggregate_metrics.csv"
echo "timestamp,total_execs,total_paths,total_crashes,total_hangs,avg_execs_per_sec" > "$AGGREGATE_LOG"

# Function to extract metrics from fuzzer_stats
extract_metrics() {
    local dir=$1
    local instance=$2
    local timestamp=$(date +%s)

    # Check if fuzzer_stats exists
    if [ ! -f "$dir/fuzzer_stats" ]; then
        return
    fi

    # Extract metrics
    local execs_per_sec=$(grep "execs_per_sec" "$dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
    local paths_total=$(grep "paths_total" "$dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
    local unique_crashes=$(grep "unique_crashes" "$dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
    local unique_hangs=$(grep "unique_hangs" "$dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
    local bitmap_cvg=$(grep "bitmap_cvg" "$dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
    local last_find=$(grep "last_find" "$dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
    local pending_favs=$(grep "pending_favs" "$dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
    local cycles_done=$(grep "cycles_done" "$dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')

    # Get process nice value
    local pid=$(grep "fuzzer_pid" "$dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
    local nice_value=0
    if [ -n "$pid" ]; then
        nice_value=$(ps -o nice= -p "$pid" 2>/dev/null || echo 0)
    fi

    # Get scheduler stats
    local scheduler_local=0
    local scheduler_global=0
    if [ -f "/sys/kernel/sched_ext/scx_simple/stats" ]; then
        local stats=$(cat /sys/kernel/sched_ext/scx_simple/stats 2>/dev/null)
        scheduler_local=$(echo "$stats" | grep -o "local=[0-9]*" | cut -d= -f2)
        scheduler_global=$(echo "$stats" | grep -o "global=[0-9]*" | cut -d= -f2)
    fi

    # Log metrics
    echo "$timestamp,$instance,$execs_per_sec,$paths_total,$unique_crashes,$unique_hangs,$bitmap_cvg,$last_find,$nice_value,$pending_favs,$cycles_done,$scheduler_local,$scheduler_global" >> "$METRICS_LOG"
}

# Function to collect aggregate metrics
collect_aggregate_metrics() {
    local timestamp=$(date +%s)
    local total_execs=0
    local total_paths=0
    local total_crashes=0
    local total_hangs=0
    local total_execs_per_sec=0
    local prefix="fuzzer"

    # Determine which prefix to use based on the output directory name
    if [[ "$FUZZER_DIR" == *"with_feedback"* ]]; then
        prefix="scheduler"
    fi

    for i in $(seq 0 $(($NUM_INSTANCES-1))); do
        local instance_dir="$FUZZER_DIR/${prefix}$i"

        if [ -f "$instance_dir/fuzzer_stats" ]; then
            # Extract metrics
            local execs=$(grep "execs_done" "$instance_dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
            local paths=$(grep "paths_total" "$instance_dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
            local crashes=$(grep "unique_crashes" "$instance_dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
            local hangs=$(grep "unique_hangs" "$instance_dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')
            local execs_per_sec=$(grep "execs_per_sec" "$instance_dir/fuzzer_stats" 2>/dev/null | awk '{print $3}')

            # Add to totals
            total_execs=$((total_execs + ${execs:-0}))
            total_paths=$((total_paths + ${paths:-0}))
            total_crashes=$((total_crashes + ${crashes:-0}))
            total_hangs=$((total_hangs + ${hangs:-0}))
            total_execs_per_sec=$(echo "$total_execs_per_sec + ${execs_per_sec:-0}" | bc)

            echo "Collected metrics from $instance_dir: execs=$execs, paths=$paths, crashes=$crashes"
        else
            echo "Warning: Stats file not found for $instance_dir"
        fi
    done

    # Calculate average executions per second
    local avg_execs_per_sec=0
    if [ "$NUM_INSTANCES" -gt 0 ]; then
        avg_execs_per_sec=$(echo "scale=2; $total_execs_per_sec / $NUM_INSTANCES" | bc)
    fi

    # Log aggregate metrics
    echo "$timestamp,$total_execs,$total_paths,$total_crashes,$total_hangs,$avg_execs_per_sec" >> "$AGGREGATE_LOG"
}

# Collect metrics for the specified duration
echo "Collecting metrics for $DURATION seconds..."
end_time=$(($(date +%s) + DURATION))

# Determine which prefix to use based on the output directory name
prefix="fuzzer"
if [[ "$FUZZER_DIR" == *"with_feedback"* ]]; then
    prefix="scheduler"
fi

while [ $(date +%s) -lt $end_time ]; do
    # Extract metrics for each instance
    for i in $(seq 0 $(($NUM_INSTANCES-1))); do
        extract_metrics "$FUZZER_DIR/${prefix}$i" "${prefix}$i"
    done

    # Collect aggregate metrics
    collect_aggregate_metrics

    # Wait for the next interval
    sleep $INTERVAL
done

echo "Metrics collection completed."
echo "Metrics are available in $OUTPUT_DIR"

# Generate plots if gnuplot is available
if command -v gnuplot &> /dev/null; then
    echo "Generating plots..."

    # Plot executions per second for each instance
    gnuplot <<EOF
    set terminal png size 800,600
    set output "$OUTPUT_DIR/execs_per_sec.png"
    set title "Executions per Second"
    set xlabel "Time (s)"
    set ylabel "Execs/sec"
    set grid
    set key outside
    plot for [i=0:$((NUM_INSTANCES-1))] "$METRICS_LOG" using 1:(\$2 eq "fuzzer".i ? \$3 : 1/0) with lines title "fuzzer".i
EOF

    # Plot total paths found for each instance
    gnuplot <<EOF
    set terminal png size 800,600
    set output "$OUTPUT_DIR/paths_total.png"
    set title "Total Paths Found"
    set xlabel "Time (s)"
    set ylabel "Paths"
    set grid
    set key outside
    plot for [i=0:$((NUM_INSTANCES-1))] "$METRICS_LOG" using 1:(\$2 eq "fuzzer".i ? \$4 : 1/0) with lines title "fuzzer".i
EOF

    # Plot aggregate metrics
    gnuplot <<EOF
    set terminal png size 800,600
    set output "$OUTPUT_DIR/aggregate_execs.png"
    set title "Total Executions"
    set xlabel "Time (s)"
    set ylabel "Executions"
    set grid
    plot "$AGGREGATE_LOG" using 1:2 with lines title "Total Executions"
EOF

    gnuplot <<EOF
    set terminal png size 800,600
    set output "$OUTPUT_DIR/aggregate_paths.png"
    set title "Total Paths Found"
    set xlabel "Time (s)"
    set ylabel "Paths"
    set grid
    plot "$AGGREGATE_LOG" using 1:3 with lines title "Total Paths"
EOF

    echo "Plots generated in $OUTPUT_DIR"
fi
