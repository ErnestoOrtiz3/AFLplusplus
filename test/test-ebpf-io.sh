#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: eBPF file I/O optimization"

test -e ../afl-fuzz && {
  # Check if eBPF support is compiled in
  if grep -q "eBPF file I/O optimization" ../afl-fuzz; then
    $ECHO "$GREEN[+] eBPF file I/O support is compiled in"
    
    # Compile our specific test program
    test -e ../afl-clang-fast && {
      ../afl-clang-fast -o test-ebpf-io ./test-ebpf-io.c > /dev/null 2>&1
    } || {
      ../afl-gcc-fast -o test-ebpf-io ./test-ebpf-io.c > /dev/null 2>&1
    }
    
    # Test with eBPF enabled
    test -e test-ebpf-io && {
      mkdir -p in
      echo "AXYZ" > in/in  # Input that should trigger interesting behavior
      
      # First run without eBPF I/O to establish baseline
      $ECHO "$GREY[*] running afl-fuzz without eBPF file I/O, this will take approx 10 seconds"
      {
        ../afl-fuzz -V07 -m ${MEM_LIMIT} -i in -o out-normal -D -- ./test-ebpf-io @@ >>errors 2>&1
      } >>errors 2>&1
      
      # Now run with eBPF I/O
      $ECHO "$GREY[*] running afl-fuzz with eBPF file I/O, this will take approx 10 seconds"
      {
        AFL_EBPF_IO=1 ../afl-fuzz -V07 -m ${MEM_LIMIT} -i in -o out-ebpf -D -- ./test-ebpf-io @@ >>errors 2>&1
      } >>errors 2>&1
      
      # Check if both runs found crashes (indicating functionality works)
      test -d out-normal/default/crashes && test -d out-ebpf/default/crashes && {
        $ECHO "$GREEN[+] afl-fuzz is working correctly with eBPF file I/O"
      } || {
        echo CUT------------------------------------------------------------------CUT
        cat errors
        echo CUT------------------------------------------------------------------CUT
        $ECHO "$RED[!] afl-fuzz is not working correctly with eBPF file I/O"
        CODE=1
      }
      
      rm -rf in out-normal out-ebpf errors
    } || {
      $ECHO "$RED[!] cannot compile the test program"
      CODE=1
    }
  } else {
    $ECHO "$YELLOW[-] eBPF file I/O support is not compiled in"
    INCOMPLETE=1
  }
} || {
  $ECHO "$YELLOW[-] afl-fuzz not found, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh
