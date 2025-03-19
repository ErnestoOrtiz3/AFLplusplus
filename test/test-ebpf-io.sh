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
$ECHO "$GREY[*] Compiling test program..."
cat > test-ebpf.c << EOF
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
  FILE *f;
  char buf[16];
  
  if (argc < 2) {
    printf("Usage: %s <filename>\n", argv[0]);
    return 1;
  }
  
  f = fopen(argv[1], "r");
  if (!f) {
    perror("fopen");
    return 2;
  }
  
  fread(buf, 1, sizeof(buf), f);
  fclose(f);
  
  return 0;
}
EOF

$AFL_CC -o test-ebpf test-ebpf.c || exit 1

# Create test directories
TESTDIR=`pwd`/test-ebpf-dir
mkdir -p "$TESTDIR/in" "$TESTDIR/out"
echo "test data" > "$TESTDIR/in/testcase"

# Run without eBPF
$ECHO "$GREY[*] Running without eBPF..."
unset AFL_EBPF_IO
../afl-fuzz -i "$TESTDIR/in" -o "$TESTDIR/out-noebpf" -V 10 -- ./test-ebpf @@ > "$TESTDIR/log-noebpf.txt" 2>&1 &
FUZZ_PID=$!
sleep 5
kill -INT $FUZZ_PID
wait $FUZZ_PID

# Extract total execs without eBPF
EXECS_NOEBPF=$(grep "total execs" "$TESTDIR/log-noebpf.txt" | tail -1 | awk '{print $3}')
$ECHO "$GREY[*] Total execs without eBPF: $EXECS_NOEBPF"

# Run with eBPF
$ECHO "$GREY[*] Running with eBPF..."
export AFL_EBPF_IO=1
../afl-fuzz -i "$TESTDIR/in" -o "$TESTDIR/out-ebpf" -V 10 -- ./test-ebpf @@ > "$TESTDIR/log-ebpf.txt" 2>&1 &
FUZZ_PID=$!
sleep 5
kill -INT $FUZZ_PID
wait $FUZZ_PID

# Extract total execs with eBPF
EXECS_EBPF=$(grep "total execs" "$TESTDIR/log-ebpf.txt" | tail -1 | awk '{print $3}')
$ECHO "$GREY[*] Total execs with eBPF: $EXECS_EBPF"

# Compare results
$ECHO "$BLUE[*] Performance comparison:"
$ECHO "    Without eBPF: $EXECS_NOEBPF execs"
$ECHO "    With eBPF:    $EXECS_EBPF execs"

# Calculate percentage difference
if [ -n "$EXECS_NOEBPF" ] && [ -n "$EXECS_EBPF" ] && [ "$EXECS_NOEBPF" -gt 0 ]; then
  PERCENT=$(( (EXECS_EBPF * 100) / EXECS_NOEBPF ))
  $ECHO "    eBPF performance: $PERCENT% of baseline"
fi

# Clean up
rm -rf "$TESTDIR" test-ebpf test-ebpf.c

$ECHO "$GREEN[+] eBPF I/O test completed successfully"
exit 0
