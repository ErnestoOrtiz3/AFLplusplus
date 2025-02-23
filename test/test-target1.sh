#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: eBPF target program execution"

# Step 1: Compile the target
test -e ../afl-cc && {
  ../afl-cc -o ebpf-target ebpf-target.c || {
    $ECHO "$RED[!] Failed to compile ebpf-target"
    CODE=1
    exit ${CODE}
  }
  
  $ECHO "$GREEN[+] Target compilation successful"

  # Create input directory and test cases
  rm -rf in out-no-ebpf out-with-ebpf input.txt
  mkdir -p in
  echo "1" > in/case1
  echo "2" > in/case2
  echo "3" > in/case3
  echo "x" > in/case4

  # Test the target directly first
  $ECHO "$GREY[*] Testing target directly..."
  ./ebpf-target in/case1
  
  # Step 2: Run without eBPF
  $ECHO "$GREY[*] Running target without eBPF, this will take approx 10 seconds"
  touch input.txt  # Ensure input file exists
  AFL_DISABLE_EBPF=1 AFL_NO_UI=1 AFL_DEBUG=1 ../afl-fuzz -V10 -m none -i in -o out-no-ebpf -f input.txt -- ./ebpf-target input.txt 2>&1 &
  FUZZER_PID=$!
  
  sleep 15  # Give it more time to generate stats
  kill -SIGINT $FUZZER_PID 2>/dev/null
  wait $FUZZER_PID 2>/dev/null

  # Step 3: Run with eBPF
  $ECHO "$GREY[*] Running target with eBPF, this will take approx 10 seconds"
  touch input.txt  # Ensure input file exists
  AFL_DEBUG=1 AFL_NO_UI=1 ../afl-fuzz -V10 -m none -i in -o out-with-ebpf -f input.txt -- ./ebpf-target input.txt 2>&1 &
  FUZZER_PID=$!
  
  sleep 15  # Give it more time to generate stats
  kill -SIGINT $FUZZER_PID 2>/dev/null
  wait $FUZZER_PID 2>/dev/null

  # Check if stats files exist
  if [ ! -f "out-no-ebpf/default/fuzzer_stats" ]; then
    $ECHO "$RED[!] No stats file found for non-eBPF run"
    ls -la out-no-ebpf/default/ 2>/dev/null || echo "Output directory not created"
    $ECHO "$RED[!] Contents of current directory:"
    ls -la
    CODE=1
    exit ${CODE}
  fi

  if [ ! -f "out-with-ebpf/default/fuzzer_stats" ]; then
    $ECHO "$RED[!] No stats file found for eBPF run"
    ls -la out-with-ebpf/default/ 2>/dev/null || echo "Output directory not created"
    $ECHO "$RED[!] Contents of current directory:"
    ls -la
    CODE=1
    exit ${CODE}
  fi

  # Capture execution stats
  NO_EBPF_EXECS=`grep execs_done out-no-ebpf/default/fuzzer_stats | awk '{print$3}'`
  EBPF_EXECS=`grep execs_done out-with-ebpf/default/fuzzer_stats | awk '{print$3}'`

  # Compare results
  if [ -n "$NO_EBPF_EXECS" ] && [ -n "$EBPF_EXECS" ]; then
    $ECHO "$GREEN[+] Execution counts - No eBPF: $NO_EBPF_EXECS, With eBPF: $EBPF_EXECS"
    
    # Extract edges found (unique paths)
    NO_EBPF_EDGES=$(grep "edges_found" out-no-ebpf/default/fuzzer_stats | awk '{print $3}')
    EBPF_EDGES=$(grep "edges_found" out-with-ebpf/default/fuzzer_stats | awk '{print $3}')
    
    # Extract corpus counts
    NO_EBPF_CORPUS=$(grep "corpus_count" out-no-ebpf/default/fuzzer_stats | awk '{print $3}')
    EBPF_CORPUS=$(grep "corpus_count" out-with-ebpf/default/fuzzer_stats | awk '{print $3}')
    
    if [ -n "$NO_EBPF_EDGES" ] && [ -n "$EBPF_EDGES" ]; then
      $ECHO "$GREEN[+] Unique edges - No eBPF: $NO_EBPF_EDGES, With eBPF: $EBPF_EDGES"
      $ECHO "$GREEN[+] Corpus size - No eBPF: $NO_EBPF_CORPUS, With eBPF: $EBPF_CORPUS"
      
      # Also show coverage percentage
      NO_EBPF_COV=$(grep "bitmap_cvg" out-no-ebpf/default/fuzzer_stats | awk '{print $3}')
      EBPF_COV=$(grep "bitmap_cvg" out-with-ebpf/default/fuzzer_stats | awk '{print $3}')
      $ECHO "$GREEN[+] Coverage - No eBPF: $NO_EBPF_COV, With eBPF: $EBPF_COV"
    else
      $ECHO "$RED[!] Failed to extract edge counts"
      CODE=1
    fi
  else
    $ECHO "$RED[!] Failed to get execution counts"
    CODE=1
  fi

} || {
  $ECHO "$RED[!] afl-cc not found, cannot compile target"
  CODE=1
}

. ./test-post.sh
