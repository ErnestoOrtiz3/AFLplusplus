#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: eBPF run counter performance comparison"

test -e ../afl-cc && {
  # Compile the test target
  ../afl-cc -o ebpf-run-counter ebpf-run-counter.c || {
    $ECHO "$RED[!] Failed to compile ebpf-run-counter"
    CODE=1
    exit ${CODE}
  }
  
  $ECHO "$GREEN[+] Target compilation successful"

  # Create input directory and test cases
  rm -rf in out-regular out-ebpf input.txt
  mkdir -p in
  echo "1" > in/case1
  echo "2" > in/case2
  echo "3" > in/case3
  echo "x" > in/case4

  # Step 1: Run with regular counter
  $ECHO "$GREY[*] Running target with regular counter, this will take approx 10 seconds"
  touch input.txt  # Ensure input file exists
  AFL_NO_UI=1 AFL_DEBUG=1 ../afl-fuzz -V10 -m none -i in -o out-regular -f input.txt -- ./ebpf-run-counter input.txt 2>&1 &
  FUZZER_PID=$!
  
  sleep 15  # Give it time to generate stats
  kill -SIGINT $FUZZER_PID 2>/dev/null
  wait $FUZZER_PID 2>/dev/null

  # Step 2: Run with eBPF counter
  $ECHO "$GREY[*] Running target with eBPF counter, this will take approx 10 seconds"
  touch input.txt  # Ensure input file exists
  AFL_USE_EBPF=1 AFL_DISABLE_REGULAR_COUNTER=1 AFL_NO_UI=1 AFL_DEBUG=1 ../afl-fuzz -V10 -m none -i in -o out-ebpf -f input.txt -- ./ebpf-run-counter input.txt 2>&1 &
  FUZZER_PID=$!
  
  sleep 15  # Give it time to generate stats
  kill -SIGINT $FUZZER_PID 2>/dev/null
  wait $FUZZER_PID 2>/dev/null

  # Check if stats files exist
  if [ ! -f "out-regular/default/fuzzer_stats" ]; then
    $ECHO "$RED[!] No stats file found for regular counter run"
    CODE=1
    exit ${CODE}
  fi
  
  if [ ! -f "out-ebpf/default/fuzzer_stats" ]; then
    $ECHO "$RED[!] No stats file found for eBPF counter run"
    CODE=1
    exit ${CODE}
  fi

  # Extract execution stats
  REGULAR_EXECS=$(grep "execs_done" out-regular/default/fuzzer_stats | awk '{print $3}')
  REGULAR_TIME=$(grep "execs_per_sec" out-regular/default/fuzzer_stats | awk '{print $3}')
  
  EBPF_EXECS=$(grep "execs_done" out-ebpf/default/fuzzer_stats | awk '{print $3}')
  EBPF_TIME=$(grep "execs_per_sec" out-ebpf/default/fuzzer_stats | awk '{print $3}')

  # Compare results
  if [ -n "$REGULAR_EXECS" ] && [ -n "$EBPF_EXECS" ] && [ -n "$REGULAR_TIME" ] && [ -n "$EBPF_TIME" ]; then
    $ECHO "$GREEN[+] Regular counter: $REGULAR_EXECS execs ($REGULAR_TIME/sec)"
    $ECHO "$GREEN[+] eBPF counter: $EBPF_EXECS execs ($EBPF_TIME/sec)"
    
    # Calculate performance difference
    PERF_DIFF=$(echo "scale=2; (($EBPF_TIME - $REGULAR_TIME) / $REGULAR_TIME) * 100" | bc)
    
    if [ $(echo "$PERF_DIFF >= 0" | bc) -eq 1 ]; then
      $ECHO "$GREEN[+] eBPF counter is $PERF_DIFF% faster than regular counter"
    else
      PERF_DIFF=$(echo "scale=2; -1 * $PERF_DIFF" | bc)
      $ECHO "$YELLOW[!] eBPF counter is $PERF_DIFF% slower than regular counter"
    fi
    
    # Check if the performance is acceptable (not more than 10% slower)
    if [ $(echo "$PERF_DIFF > 10" | bc) -eq 1 ] && [ $(echo "$EBPF_TIME < $REGULAR_TIME" | bc) -eq 1 ]; then
      $ECHO "$RED[!] eBPF counter performance is significantly worse (>10% slower)"
      CODE=1
    fi
  else
    $ECHO "$RED[!] Failed to get execution counts or timing information"
    CODE=1
  fi

} || {
  $ECHO "$RED[!] afl-cc not found, cannot compile target"
  CODE=1
}

. ./test-post.sh