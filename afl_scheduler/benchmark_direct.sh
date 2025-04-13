#!/bin/bash

# AFL++ Scheduler Benchmark Script (Direct BPF Map Access Version)
# Usage: ./benchmark_direct.sh [duration_minutes] [num_instances] [target_program] [target_args] [scheduler_order] [memory_limit] [timeout]
# scheduler_order: "custom_first" (default) or "cfs_first"
# memory_limit: "none" (default) or a specific value in MB
# timeout: "5000+" (default) or a specific value in milliseconds

set -e

# Default parameters
DURATION=${1:-60}  # minutes
NUM_INSTANCES=${2:-4}
TARGET_PROGRAM=${3:-"./target_binary"}
TARGET_ARGS=${4:-"@@"}
SCHEDULER_ORDER=${5:-"custom_first"}  # New parameter
MEMORY_LIMIT=${6:-"none"}  # Default to no memory limit
TIMEOUT=${7:-"5000+"}  # Default to 5 seconds with auto-calibration
STATS_INTERVAL=30  # seconds

# Validate scheduler_order parameter
if [[ "$SCHEDULER_ORDER" != "custom_first" && "$SCHEDULER_ORDER" != "cfs_first" ]]; then
    echo "Error: scheduler_order must be either 'custom_first' or 'cfs_first'"
    exit 1
fi

# Get the absolute path to the AFL++ directory
AFL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export PATH="${AFL_DIR}:${PATH}"

# Convert DURATION from minutes to seconds
DURATION_SECONDS=$((DURATION * 60))

# Directories
BASE_DIR="${AFL_DIR}/benchmark_results"
CUSTOM_DIR="${BASE_DIR}/custom_scheduler"
CFS_DIR="${BASE_DIR}/cfs_scheduler"
STATS_DIR="${BASE_DIR}/stats"

# Function to clear system caches
clear_system_caches() {
    echo "Clearing system caches..."
    sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 2  # Give system time to stabilize
}

# Before running benchmarks, clean up any previous results
clean_previous_results() {
    echo "Cleaning up previous benchmark results..."
    if [ -d "${CUSTOM_DIR}" ]; then
        rm -rf "${CUSTOM_DIR}"
    fi
    if [ -d "${CFS_DIR}" ]; then
        rm -rf "${CFS_DIR}"
    fi
}

# Add this call near the beginning of the script, before running any benchmarks
clean_previous_results

# Create directories
mkdir -p "${CUSTOM_DIR}" "${CFS_DIR}" "${STATS_DIR}"

# Create original_seeds directory if it doesn't exist
if [ ! -d "${AFL_DIR}/original_seeds" ]; then
    mkdir -p "${AFL_DIR}/original_seeds"
    # If input_dir already exists and has files, back them up
    if [ -d "${AFL_DIR}/input_dir" ] && [ "$(ls -A ${AFL_DIR}/input_dir 2>/dev/null)" ]; then
        cp "${AFL_DIR}/input_dir"/* "${AFL_DIR}/original_seeds/"
    else
        # Create a minimal test case
        mkdir -p "${AFL_DIR}/input_dir"
        echo "test" > "${AFL_DIR}/original_seeds/seed"
        cp "${AFL_DIR}/original_seeds/seed" "${AFL_DIR}/input_dir/"
    fi
fi

# Initialize arrays for PIDs
declare -a SECONDARY_PIDS=()

# Function definition
run_afl_instances() {
    local output_dir=$1
    
    # Start main instance
    cd "${AFL_DIR}"  # Change to AFL++ directory
    
    # Execute main instance. Skip AFL++ CPU frequency checks for more precise benchmarking
    AFL_SKIP_CPUFREQ=1 "${AFL_DIR}/afl-fuzz" -i "${AFL_DIR}/input_dir" -o "${output_dir}" -M main -m ${MEMORY_LIMIT} -t ${TIMEOUT} -- ${TARGET_PROGRAM} ${TARGET_ARGS} &
    
    MAIN_PID=$!
    
    # Start secondary instances
    for i in $(seq 1 $((NUM_INSTANCES - 1))); do
        AFL_SKIP_CPUFREQ=1 "${AFL_DIR}/afl-fuzz" -i "${AFL_DIR}/input_dir" -o "${output_dir}" -S "secondary${i}" -m ${MEMORY_LIMIT} -t ${TIMEOUT} -- ${TARGET_PROGRAM} ${TARGET_ARGS} &
        SECONDARY_PIDS+=($!)
    done
    
    echo "Started ${NUM_INSTANCES} AFL++ instances with memory limit: ${MEMORY_LIMIT}, timeout: ${TIMEOUT}"
}

# Function to collect stats
collect_stats() {
    local output_file="${STATS_DIR}/$1_summary.txt"
    
    echo "Collecting stats for $1..."
    
    # Run afl-whatsup
    echo "=== AFL++ Status ===" > "${output_file}"
    "${AFL_DIR}/afl-whatsup" -s "${2}" >> "${output_file}"
    
    # Collect individual fuzzer stats
    echo -e "\n=== Individual Fuzzer Stats ===" >> "${output_file}"
    for dir in "${2}"/*/; do
        if [ -d "${dir}" ] && [ -f "${dir}/fuzzer_stats" ]; then
            echo -e "\n--- $(basename ${dir}) ---" >> "${output_file}"
            cat "${dir}/fuzzer_stats" | grep -E "execs_per_sec|execs_done|paths_total|unique_crashes|cycles_done|edges_found|bitmap_cvg|stability" >> "${output_file}"
        fi
    done
}

# Function to reset input directory
reset_input_dir() {
    echo "Resetting input directory..."
    rm -rf "${AFL_DIR}/input_dir"
    mkdir -p "${AFL_DIR}/input_dir"
    # Copy original seed files back to input directory
    cp "${AFL_DIR}/original_seeds"/* "${AFL_DIR}/input_dir/" 2>/dev/null || echo "No original seeds found, creating minimal test case"
    # Create a minimal test case if no original seeds exist
    if [ ! "$(ls -A ${AFL_DIR}/input_dir 2>/dev/null)" ]; then
        echo "test" > "${AFL_DIR}/input_dir/seed"
    fi
}

# Function to run benchmark with a specific scheduler
run_benchmark_with_scheduler() {
    local scheduler_type=$1
    local output_dir=$2
    
    echo "=== Running with ${scheduler_type} scheduler ==="
    
    # Reset input directory before run
    reset_input_dir
    
    # Clear system caches
    clear_system_caches
    
    if [[ "$scheduler_type" == "custom" ]]; then
        echo "Loading AFL scheduler (direct BPF map access version)..."
        cd "${AFL_DIR}/afl_scheduler"
        
        # Use the new direct BPF map access binaries
        sudo ./afl_sched_loader &
        LOADER_PID=$!
        sleep 2  # Give the loader time to initialize
        
        # Start the direct monitor
        ./afl_monitor_direct &
        MONITOR_PID=$!
        
        # Start stats collector if available
        if [ -x "./stats_collector" ]; then
            ./stats_collector ${STATS_INTERVAL} "${STATS_DIR}/custom" &
            STATS_PID=$!
        else
            echo "Warning: stats_collector not found or not executable"
        fi
    fi
    
    # Run AFL instances
    cd "${AFL_DIR}"
    run_afl_instances "${output_dir}"
    
    echo "Running for ${DURATION} minutes..."
    sleep ${DURATION_SECONDS}
    
    # Kill AFL instances
    echo "Stopping AFL instances..."
    if [ -n "${MAIN_PID}" ]; then
        kill -SIGINT ${MAIN_PID} 2>/dev/null || true
    fi
    
    for pid in "${SECONDARY_PIDS[@]}"; do
        if [ -n "${pid}" ]; then
            kill -SIGINT ${pid} 2>/dev/null || true
        fi
    done
    
    wait ${MAIN_PID} ${SECONDARY_PIDS[@]} 2>/dev/null || true
    SECONDARY_PIDS=()
    
    # Kill monitor processes if running
    if [[ "$scheduler_type" == "custom" ]]; then
        if [ -n "${MONITOR_PID}" ]; then
            kill ${MONITOR_PID} 2>/dev/null || true
            wait ${MONITOR_PID} 2>/dev/null || true
        fi
        
        if [ -n "${STATS_PID}" ]; then
            kill ${STATS_PID} 2>/dev/null || true
            wait ${STATS_PID} 2>/dev/null || true
        fi
        
        # Unload the scheduler
        if [ -n "${LOADER_PID}" ]; then
            kill ${LOADER_PID} 2>/dev/null || true
            wait ${LOADER_PID} 2>/dev/null || true
        fi
    fi
    
    # Collect final stats
    collect_stats "${scheduler_type}" "${output_dir}"
}

# Run benchmarks in the specified order
if [[ "$SCHEDULER_ORDER" == "custom_first" ]]; then
    run_benchmark_with_scheduler "custom" "${CUSTOM_DIR}"
    run_benchmark_with_scheduler "cfs" "${CFS_DIR}"
else
    run_benchmark_with_scheduler "cfs" "${CFS_DIR}"
    run_benchmark_with_scheduler "custom" "${CUSTOM_DIR}"
fi

# Generate comparison report
echo -e "\n=== Generating comparison report ==="
cd "${AFL_DIR}"
python3 afl_scheduler/compare_results.py "${CUSTOM_DIR}" "${CFS_DIR}" "${STATS_DIR}" > "${BASE_DIR}/comparison_report.txt"

echo "Benchmark complete. Results in ${BASE_DIR}/comparison_report.txt"