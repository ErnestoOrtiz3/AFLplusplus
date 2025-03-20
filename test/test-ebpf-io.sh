#!/bin/sh

# Test script for eBPF I/O functionality
# This compares execution performance with and without eBPF enabled

. ./test-common.sh

test -z "$AFL_CC" && AFL_CC="$CC"

$ECHO "$BLUE[*] Testing: eBPF I/O functionality"

# Check if eBPF support is compiled in
$ECHO "$GREY[*] Checking if eBPF support is available..."
if ! grep -q "define USE_EBPF" ../config.h; then
  $ECHO "$YELLOW[-] eBPF support not compiled, skipping test"
  exit 0
fi

# Compile a simple test program that reads from a file
$ECHO "$GREY[*] Compiling test program with AFL instrumentation..."
cat > test-ebpf.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int main(int argc, char **argv) {
  FILE *f;
  char buf[64];
  
  if (argc < 2) {
    printf("Usage: %s <filename>\n", argv[0]);
    return 1;
  }
  
  f = fopen(argv[1], "r");
  if (!f) {
    perror("fopen");
    return 2;
  }
  
  size_t bytes_read = fread(buf, 1, sizeof(buf), f);
  fclose(f);
  
  // Add some branching logic to make it interesting for the fuzzer
  if (bytes_read > 0) {
    if (buf[0] == 'A') {
      printf("Found A\n");
    } else if (buf[0] == 'B') {
      printf("Found B\n");
    } else {
      printf("Found something else\n");
    }
    
    if (bytes_read > 1) {
      if (buf[1] == '1') {
        printf("Found 1\n");
      } else if (buf[1] == '2') {
        printf("Found 2\n");
      } else {
        printf("Found another character\n");
      }
    }
  }
  
  return 0;
}
EOF

# Use AFL compiler to instrument the code
test -z "$AFL_CC" && AFL_CC="../afl-cc"
$ECHO "$GREY[*] Using compiler: $AFL_CC"

# Try different instrumentation methods
if [ -x "../afl-clang-fast" ]; then
  $ECHO "$GREY[*] Using afl-clang-fast for instrumentation"
  ../afl-clang-fast -o test-ebpf test-ebpf.c || exit 1
elif [ -x "../afl-gcc" ]; then
  $ECHO "$GREY[*] Using afl-gcc for instrumentation"
  ../afl-gcc -o test-ebpf test-ebpf.c || exit 1
else
  $ECHO "$GREY[*] Using generic afl-cc for instrumentation"
  $AFL_CC -o test-ebpf test-ebpf.c || exit 1
fi
$ECHO "$GREEN[+] Target compilation successful"

# Create test directories with proper permissions
TESTDIR=`pwd`/test-ebpf-dir
mkdir -p "$TESTDIR/in" "$TESTDIR/out-noebpf" "$TESTDIR/out-ebpf"
echo "A1test data" > "$TESTDIR/in/testcase"
chmod -R 777 "$TESTDIR"

# Debug: Check if afl-fuzz is available
$ECHO "$GREY[*] Checking afl-fuzz..."
if [ ! -x "../afl-fuzz" ]; then
  $ECHO "$RED[!] afl-fuzz not found or not executable"
  exit 1
fi

# Debug: Check if test-ebpf is available
if [ ! -x "./test-ebpf" ]; then
  $ECHO "$RED[!] test-ebpf not found or not executable"
  exit 1
fi

# Verify that the binary is instrumented
$ECHO "$GREY[*] Verifying instrumentation..."
$ECHO "$GREY[*] Command: ../afl-showmap -m none -o /dev/null -- ./test-ebpf \"$TESTDIR/in/testcase\""
../afl-showmap -m none -o test-map.txt -- ./test-ebpf "$TESTDIR/in/testcase" > test-showmap.log 2>&1
RESULT=$?
if [ $RESULT -ne 0 ]; then
  $ECHO "$RED[!] Instrumentation verification failed with code $RESULT"
  $ECHO "$GREY[*] afl-showmap output:"
  cat test-showmap.log
  exit 1
fi
$ECHO "$GREEN[+] Binary appears to be properly instrumented"

# Run without eBPF
$ECHO "$GREY[*] Running without eBPF..."
unset AFL_EBPF_IO
$ECHO "$GREY[*] Command: ../afl-fuzz -i \"$TESTDIR/in\" -o \"$TESTDIR/out-noebpf\" -V 30 -- ./test-ebpf @@"
../afl-fuzz -i "$TESTDIR/in" -o "$TESTDIR/out-noebpf" -V 30 -- ./test-ebpf @@ > "$TESTDIR/log-noebpf.txt" 2>&1 &
FUZZ_PID=$!
if [ -z "$FUZZ_PID" ]; then
  $ECHO "$RED[!] Failed to start afl-fuzz"
  exit 1
fi
$ECHO "$GREY[*] Started afl-fuzz with PID $FUZZ_PID"

# Wait for afl-fuzz to initialize and run
sleep 10
ps -p $FUZZ_PID > /dev/null 2>&1
if [ $? -eq 0 ]; then
  $ECHO "$GREY[*] afl-fuzz is still running, waiting for completion..."
  # Wait for afl-fuzz to complete (it should exit after -V 30 seconds)
  wait $FUZZ_PID 2>/dev/null || true
else
  $ECHO "$YELLOW[!] afl-fuzz process not running, checking logs..."
  cat "$TESTDIR/log-noebpf.txt"
fi

# Run with eBPF
$ECHO "$GREY[*] Running with eBPF..."
export AFL_EBPF_IO=1
$ECHO "$GREY[*] Command: ../afl-fuzz -i \"$TESTDIR/in\" -o \"$TESTDIR/out-ebpf\" -V 30 -- ./test-ebpf @@"
../afl-fuzz -i "$TESTDIR/in" -o "$TESTDIR/out-ebpf" -V 30 -- ./test-ebpf @@ > "$TESTDIR/log-ebpf.txt" 2>&1 &
FUZZ_PID=$!
if [ -z "$FUZZ_PID" ]; then
  $ECHO "$RED[!] Failed to start afl-fuzz"
  exit 1
fi
$ECHO "$GREY[*] Started afl-fuzz with PID $FUZZ_PID"

# Wait for afl-fuzz to initialize and run
sleep 10
ps -p $FUZZ_PID > /dev/null 2>&1
if [ $? -eq 0 ]; then
  $ECHO "$GREY[*] afl-fuzz is still running, waiting for completion..."
  # Wait for afl-fuzz to complete (it should exit after -V 30 seconds)
  wait $FUZZ_PID 2>/dev/null || true
else
  $ECHO "$YELLOW[!] afl-fuzz process not running, checking logs..."
  cat "$TESTDIR/log-ebpf.txt"
fi

# Check if stats files exist
if [ ! -f "$TESTDIR/out-noebpf/default/fuzzer_stats" ]; then
  $ECHO "$RED[!] No stats file found for non-eBPF run"
  ls -la "$TESTDIR/out-noebpf/default/" 2>/dev/null || echo "Output directory not created"
  $ECHO "$RED[!] Contents of output directory:"
  ls -la "$TESTDIR/out-noebpf/"
  exit 1
fi

if [ ! -f "$TESTDIR/out-ebpf/default/fuzzer_stats" ]; then
  $ECHO "$RED[!] No stats file found for eBPF run"
  ls -la "$TESTDIR/out-ebpf/default/" 2>/dev/null || echo "Output directory not created"
  $ECHO "$RED[!] Contents of output directory:"
  ls -la "$TESTDIR/out-ebpf/"
  exit 1
fi

# Capture execution stats
EXECS_NOEBPF=$(grep execs_done "$TESTDIR/out-noebpf/default/fuzzer_stats" | awk '{print $3}')
EXECS_EBPF=$(grep execs_done "$TESTDIR/out-ebpf/default/fuzzer_stats" | awk '{print $3}')

# Get execs_per_sec for performance comparison
EXECS_PER_SEC_NOEBPF=$(grep execs_per_sec "$TESTDIR/out-noebpf/default/fuzzer_stats" | awk '{print $3}')
EXECS_PER_SEC_EBPF=$(grep execs_per_sec "$TESTDIR/out-ebpf/default/fuzzer_stats" | awk '{print $3}')

# Compare results
$ECHO "$BLUE[*] Performance comparison:"
$ECHO "    Without eBPF: $EXECS_NOEBPF total execs, $EXECS_PER_SEC_NOEBPF execs/sec"
$ECHO "    With eBPF:    $EXECS_EBPF total execs, $EXECS_PER_SEC_EBPF execs/sec"

# Calculate performance difference as a percentage
if [ -n "$EXECS_PER_SEC_NOEBPF" ] && [ -n "$EXECS_PER_SEC_EBPF" ] && [ "$(echo "$EXECS_PER_SEC_NOEBPF > 0" | bc -l)" -eq 1 ]; then
  PERF_DIFF=$(echo "scale=2; ($EXECS_PER_SEC_EBPF - $EXECS_PER_SEC_NOEBPF) * 100 / $EXECS_PER_SEC_NOEBPF" | bc)
  if [ "$(echo "$PERF_DIFF >= 0" | bc -l)" -eq 1 ]; then
    $ECHO "$GREEN[+] eBPF performance: $PERF_DIFF% faster"
  else
    $ECHO "$YELLOW[!] eBPF performance: ${PERF_DIFF#-}% slower"
  fi
fi

# Extract additional stats for more comprehensive comparison
NO_EBPF_EDGES=$(grep "edges_found" "$TESTDIR/out-noebpf/default/fuzzer_stats" | awk '{print $3}')
EBPF_EDGES=$(grep "edges_found" "$TESTDIR/out-ebpf/default/fuzzer_stats" | awk '{print $3}')

NO_EBPF_CORPUS=$(grep "corpus_count" "$TESTDIR/out-noebpf/default/fuzzer_stats" | awk '{print $3}')
EBPF_CORPUS=$(grep "corpus_count" "$TESTDIR/out-ebpf/default/fuzzer_stats" | awk '{print $3}')

NO_EBPF_COV=$(grep "bitmap_cvg" "$TESTDIR/out-noebpf/default/fuzzer_stats" | awk '{print $3}')
EBPF_COV=$(grep "bitmap_cvg" "$TESTDIR/out-ebpf/default/fuzzer_stats" | awk '{print $3}')

# Display additional stats
$ECHO "$BLUE[*] Unique edges:"
$ECHO "    Without eBPF: $NO_EBPF_EDGES"
$ECHO "    With eBPF:    $EBPF_EDGES"

$ECHO "$BLUE[*] Corpus size:"
$ECHO "    Without eBPF: $NO_EBPF_CORPUS"
$ECHO "    With eBPF:    $EBPF_CORPUS"

$ECHO "$BLUE[*] Coverage:"
$ECHO "    Without eBPF: $NO_EBPF_COV"
$ECHO "    With eBPF:    $EBPF_COV"

# Clean up
rm -rf "$TESTDIR" test-ebpf test-ebpf.c

$ECHO "$GREEN[+] eBPF I/O test completed successfully"
exit 0
