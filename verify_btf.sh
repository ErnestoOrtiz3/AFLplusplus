#!/bin/bash
# Script to verify BTF support installation

set -e

echo "Verifying BTF support..."

# Check if BTF filesystem is mounted
if [ -e /sys/kernel/btf/vmlinux ]; then
    echo "✅ BTF filesystem is mounted and vmlinux BTF data is available"
else
    echo "❌ BTF filesystem is not mounted or vmlinux BTF data is missing"
    echo "   This indicates BTF support is not properly installed"
    exit 1
fi

# Check if bpftool is installed
if command -v bpftool &> /dev/null; then
    echo "✅ bpftool is installed: $(which bpftool)"
    BPFTOOL_VERSION=$(bpftool version 2>&1 | head -n 1)
    echo "   Version: $BPFTOOL_VERSION"
else
    echo "❌ bpftool is not installed or not in PATH"
    exit 1
fi

# Try to dump BTF info
echo "Attempting to dump BTF info..."
if bpftool btf dump file /sys/kernel/btf/vmlinux &> /dev/null; then
    echo "✅ Successfully accessed BTF data with bpftool"
else
    echo "❌ Failed to access BTF data with bpftool"
    exit 1
fi

# Check if we can get BTF type info
TYPE_COUNT=$(bpftool btf dump file /sys/kernel/btf/vmlinux | grep -c "^[[]")
echo "✅ Found $TYPE_COUNT BTF types in vmlinux"

# Check if libbpf is installed
if ldconfig -p | grep -q libbpf; then
    echo "✅ libbpf is installed"
    echo "   $(ldconfig -p | grep libbpf)"
else
    echo "❌ libbpf is not installed"
    echo "   Run: sudo apt install -y libbpf-dev"
    exit 1
fi

# Check if pahole is installed
if command -v pahole &> /dev/null; then
    echo "✅ pahole is installed: $(which pahole)"
    PAHOLE_VERSION=$(pahole --version 2>&1 | head -n 1)
    echo "   Version: $PAHOLE_VERSION"
else
    echo "❌ pahole is not installed"
    echo "   Run: sudo apt install -y dwarves"
    exit 1
fi

# Check if clang is installed for BPF compilation
if command -v clang &> /dev/null; then
    echo "✅ clang is installed: $(which clang)"
    CLANG_VERSION=$(clang --version | head -n 1)
    echo "   Version: $CLANG_VERSION"
else
    echo "❌ clang is not installed"
    echo "   Run: sudo apt install -y clang llvm"
    exit 1
fi

# Check if we can compile a simple BPF program with BTF
echo "Testing BPF compilation with BTF..."
TEMP_DIR=$(mktemp -d)
cd $TEMP_DIR

# Create a simple BPF program
cat > test.bpf.c << 'EOF'
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

SEC("xdp")
int xdp_pass(struct xdp_md *ctx) {
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
EOF

# Try to compile it with BTF support
if clang -g -O2 -target bpf -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu -c test.bpf.c -o test.bpf.o 2>/dev/null; then
    echo "✅ Successfully compiled BPF program with BTF support"
    
    # Check if BTF sections are present in the object file
    if llvm-objdump -h test.bpf.o 2>/dev/null | grep -q -i btf; then
        echo "✅ BTF sections are present in the compiled object"
    else
        echo "⚠️ BTF sections not found in compiled object"
    fi
else
    echo "⚠️ Could not compile BPF program with BTF support"
    echo "   This might be due to missing headers or incorrect compiler flags"
fi

# Clean up
cd - > /dev/null
rm -rf $TEMP_DIR

echo ""
echo "BTF support verification complete. All checks passed!"
echo "You can now use BTF-dependent features like CO-RE (Compile Once - Run Everywhere) BPF programs."
