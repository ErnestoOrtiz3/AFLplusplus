#!/bin/bash

# Script to instrument and fuzz the complex target with AFL++

# Ensure we have the necessary directories
mkdir -p output_dir

# Compile the target with AFL++ instrumentation
echo "Compiling complex_target with AFL++ instrumentation..."
afl-cc -o complex_target_afl complex_target.c -lm

# Check if compilation was successful
if [ ! -f "complex_target_afl" ]; then
    echo "Error: Failed to compile complex_target with AFL++"
    exit 1
fi

# Run AFL++ fuzzer
echo "Starting AFL++ fuzzer..."
afl-fuzz -i ./ -o output_dir -m none -t 1000 -- ./complex_target_afl @@
