#!/bin/bash

# AFL++ Scheduler Benchmark Script
# Usage: ./benchmark.sh [duration_minutes] [num_instances] [target_program] [target_args]

set -e # makes the script exit immediately if ANY command within it exits with a non-zero status (indicating an error).
# Without set -e, a Bash script would normally continue running even if individual commands fail, which could lead to unexpected behavior or additional errors.

# Default parameters
# They're variables, but their initialization is dynamic based on what arguments are passed to the script.
# The syntax ${parameter:-default} is Bash parameter expansion that uses the parameter's value if it's set, or the default value if the parameter is unset or null.
DURATION=${1:-60}  # minutes. It uses the first command-line argument ($1) if provided, otherwise defaults to 60 minutes.
NUM_INSTANCES=${2:-4}
TARGET_PROGRAM=${3:-"./target_binary"}
TARGET_ARGS=${4:-"@@"}
STATS_INTERVAL=30  # seconds

# Get the absolute path to the AFL++ directory
# This line determines the absolute path to the AFL++ directory by:
# ${BASH_SOURCE[0]} - Gets the path to the current script file
# dirname "${BASH_SOURCE[0]}" - Extracts the directory containing the script
# cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd - Changes directory to the parent of the script's directory and gets the absolute path
# The result is stored in the AFL_DIR variable
AFL_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"


export PATH="${AFL_DIR}:${PATH}"
#This line is modifying the PATH environment variable by prepending the AFL++ directory (${AFL_DIR}) to it. This means:
#The script is adding the AFL++ directory to the system's search path
#When the script later tries to execute AFL++ binaries without specifying their full path, the system will first look in the AFL++ directory
#This approach allows the script to run AFL++ commands like afl-fuzz without specifying their full path. However, it's not directly finding binaries - it's just making them findable through the standard command lookup mechanism.
#Later in the script, when commands like "${AFL_DIR}/afl-fuzz" are used, those are direct references using the absolute path. So the script actually uses both approaches:
#It modifies PATH to make AFL++ commands available by name
#It also uses direct absolute paths in many places for clarity and reliability
#This provides flexibility while ensuring the correct binaries are used regardless of what might be in the system PATH.





# Convert DURATION from minutes to seconds. (sleep will need seconds argument)
# By converting the user-friendly input (minutes) to the format needed by the system command (seconds), 
# the script maintains a good user experience while still working correctly with system utilities.
DURATION_SECONDS=$((DURATION * 60))


# Before running benchmarks, clean up any previous results
clean_previous_results() {
    echo "Cleaning up previous benchmark results..."
    if [ -d "${CUSTOM_DIR}" ]; then
        rm -rf "${CUSTOM_DIR}"
    fi
    if [ -d "${CFS_DIR}" ]; then
        rm -rf "${CFS_DIR}"
    fi
    # mkdir -p "${CUSTOM_DIR}" "${CFS_DIR}" "${STATS_DIR}"
}

# Add this call near the beginning of the script, before running any benchmarks
clean_previous_results

# Directories
BASE_DIR="${AFL_DIR}/benchmark_results"
CUSTOM_DIR="${BASE_DIR}/custom_scheduler"
CFS_DIR="${BASE_DIR}/cfs_scheduler"
STATS_DIR="${BASE_DIR}/stats"

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
    local output_dir=$1 # local means the variable is local to the function
    # Assigns the value of the first argument passed to the function ($1)
    
    # Start main instance
    cd "${AFL_DIR}"  # Change to AFL++ directory
    
    # Execute main instance. Skip AFL++ CPU frequency checks for more precise benchmarking
    AFL_SKIP_CPUFREQ=1 "${AFL_DIR}/afl-fuzz" -i "${AFL_DIR}/input_dir" -o "${output_dir}" -M main -- ${TARGET_PROGRAM} ${TARGET_ARGS} &
    
    
    MAIN_PID=$! # $! is a special variable that contains the PID of the most recently executed background command
    
    # Start secondary instances
    for i in $(seq 1 $((NUM_INSTANCES - 1))); do
        AFL_SKIP_CPUFREQ=1 "${AFL_DIR}/afl-fuzz" -i "${AFL_DIR}/input_dir" -o "${output_dir}" -S "secondary${i}" -- ${TARGET_PROGRAM} ${TARGET_ARGS} &
        SECONDARY_PIDS+=($!)
    done
    
    echo "Started ${NUM_INSTANCES} AFL++ instances"
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



# Run with custom scheduler
echo "=== Running with custom AFL scheduler ==="
echo "Loading AFL scheduler..."
cd "${AFL_DIR}/afl_scheduler"
./afl_sched_ctl.sh start || { echo "Failed to load custom scheduler"; exit 1; }

# Reset input directory before first run
reset_input_dir

# Start stats collector
if [ -x "./stats_collector" ]; then
    ./stats_collector ${STATS_INTERVAL} "${STATS_DIR}/custom" &
    STATS_PID=$!
else
    echo "Warning: stats_collector not found or not executable"
fi

# Run AFL instances
cd "${AFL_DIR}"  # Return to AFL++ directory
run_afl_instances "${CUSTOM_DIR}"

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

# Kill stats collector
if [ -n "${STATS_PID}" ]; then
    kill ${STATS_PID} 2>/dev/null || true
    wait ${STATS_PID} 2>/dev/null || true
fi

# Unload scheduler
cd "${AFL_DIR}/afl_scheduler"
./afl_sched_ctl.sh stop || echo "Warning: Failed to unload scheduler"

# Collect final stats
collect_stats "custom" "${CUSTOM_DIR}"

# Run with CFS scheduler
echo -e "\n=== Running with standard CFS scheduler ==="

# Reset input directory before second run
reset_input_dir

# Run AFL instances
cd "${AFL_DIR}"  # Return to AFL++ directory
run_afl_instances "${CFS_DIR}"

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

# Collect final stats
collect_stats "cfs" "${CFS_DIR}"

# Generate comparison report
echo -e "\n=== Generating comparison report ==="
cd "${AFL_DIR}"
python3 afl_scheduler/compare_results.py "${CUSTOM_DIR}" "${CFS_DIR}" "${STATS_DIR}" > "${BASE_DIR}/comparison_report.txt"

echo "Benchmark complete. Results in ${BASE_DIR}/comparison_report.txt"
