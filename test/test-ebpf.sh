#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: eBPF support"

test -e ../afl-fuzz && {
  # First test: Verify eBPF support is compiled in
  grep -q "eBPF support available" ../afl-fuzz && {
    $ECHO "$GREEN[+] eBPF support present"
  } || {
    $ECHO "$RED[!] eBPF support not present"
    CODE=1
  }

  # Second test: Basic eBPF context initialization
  AFL_DEBUG=1 ../afl-fuzz -V 2>&1 | grep -q "eBPF context initialized" && {
    $ECHO "$GREEN[+] eBPF context initialization successful"
  } || {
    $ECHO "$RED[!] eBPF context initialization failed"
    CODE=1
  }
} || {
  $ECHO "$YELLOW[-] afl-fuzz not compiled, cannot test"
  INCOMPLETE=1
}

. ./test-post.sh