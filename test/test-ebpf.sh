#!/bin/sh

. ./test-pre.sh

$ECHO "$BLUE[*] Testing: eBPF performance monitoring"

# Check if we're on Linux first
if [ "$(uname -s)" != "Linux" ]; then
    $ECHO "$YELLOW[-] eBPF testing skipped - not on Linux"
    exit 0
fi

# Test program with predictable behavior for eBPF stats
cat > test-ebpf-target.c <<EOF
#include <stdio.h>
#include <unistd.h>

int main(int argc, char** argv) {
    char buf[100];
    if (read(0, buf, sizeof(buf)) > 0) {
        // Predictable branch for testing
        if (buf[0] == 'A') {
            for (int i = 0; i < 1000000; i++) {
                // CPU intensive operation
                asm volatile("nop");
            }
        }
    }
    return 0;
}
EOF

# Compile test program
test -e ../afl-clang-fast && {
    ../afl-clang-fast -o test-ebpf-target test-ebpf-target.c > /dev/null 2>&1
} || {
    ../afl-gcc-fast -o test-ebpf-target test-ebpf-target.c > /dev/null 2>&1
}

if [ ! -e test-ebpf-target ]; then
    $ECHO "$RED[!] Cannot compile test program"
    CODE=1
    exit $CODE
fi

# Create test input directory
mkdir -p in
echo "Test" > in/default
echo "AAAA" > in/trigger

# Test without root/capabilities first - should fall back gracefully
$ECHO "$GREY[*] Testing eBPF fallback behavior (without privileges)"
{
    export AFL_DEBUG=1
    ../afl-fuzz -V10 -m none -i in -o out-nopriv -- ./test-ebpf-target > test-ebpf.log 2>&1
} > /dev/null 2>&1

if ! grep -q "Falling back to traditional stats" test-ebpf.log; then
    $ECHO "$RED[!] eBPF fallback message not found when running without privileges"
    CODE=1
else
    $ECHO "$GREEN[+] eBPF fallback behavior working correctly"
fi

# Test with sudo if available
if command -v sudo >/dev/null 2>&1; then
    $ECHO "$GREY[*] Testing eBPF with sudo (this will prompt for password)"
    {
        sudo ../afl-fuzz -V10 -m none -i in -o out-priv -- ./test-ebpf-target > test-ebpf-sudo.log 2>&1
    } > /dev/null 2>&1

    if ! grep -q "eBPF stats collection initialized" test-ebpf-sudo.log; then
        $ECHO "$RED[!] eBPF initialization failed even with sudo"
        CODE=1
    else
        $ECHO "$GREEN[+] eBPF performance monitoring working with sudo"
        
        # Verify stats collection
        if grep -q "branch_misses:" out-priv/default/fuzzer_stats; then
            $ECHO "$GREEN[+] eBPF performance metrics being collected"
        else
            $ECHO "$RED[!] eBPF performance metrics not found in fuzzer_stats"
            CODE=1
        fi
    fi
else
    $ECHO "$YELLOW[-] Skipping sudo tests - sudo not available"
fi

# Cleanup
rm -f test-ebpf-target test-ebpf-target.c test-ebpf.log test-ebpf-sudo.log
rm -rf in out-nopriv out-priv

exit $CODE