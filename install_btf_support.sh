#!/bin/bash
# Script to install BTF support on Ubuntu 24.04

set -e

echo "Installing BTF support packages..."

# Install required packages
sudo apt update
sudo apt install -y linux-tools-common linux-tools-generic linux-headers-generic
sudo apt install -y libbpf-dev

# Install bpftool through linux-tools package
KERNEL_VERSION=$(uname -r)
echo "Installing bpftool for kernel $KERNEL_VERSION..."
sudo apt install -y linux-tools-$KERNEL_VERSION || {
  echo "Could not install linux-tools-$KERNEL_VERSION, trying generic version..."
  sudo apt install -y linux-tools-generic
}

# Verify bpftool is installed
if ! command -v bpftool &> /dev/null; then
  echo "bpftool not found in PATH. Searching for it..."
  BPFTOOL_PATH=$(find /usr/lib -name bpftool -type f 2>/dev/null | head -n 1)
  if [ -n "$BPFTOOL_PATH" ]; then
    echo "Found bpftool at $BPFTOOL_PATH"
    sudo ln -sf "$BPFTOOL_PATH" /usr/local/bin/bpftool
    echo "Created symlink to /usr/local/bin/bpftool"
  else
    echo "ERROR: Could not find bpftool. Please install it manually."
    exit 1
  fi
fi

# Check if pahole is installed
if ! command -v pahole &> /dev/null; then
    echo "Installing pahole (dwarves package)..."
    sudo apt install -y dwarves
fi

# Generate BTF info for the running kernel if it doesn't exist
if [ ! -e /sys/kernel/btf/vmlinux ]; then
    echo "Generating BTF information for the running kernel..."
    
    # Create temporary directory
    TEMP_DIR=$(mktemp -d)
    cd $TEMP_DIR
    
    # Get kernel release
    KERNEL_RELEASE=$(uname -r)
    
    # Try to find vmlinux
    VMLINUX_PATH=""
    for path in /boot/vmlinux-$KERNEL_RELEASE /usr/lib/debug/boot/vmlinux-$KERNEL_RELEASE; do
        if [ -f "$path" ]; then
            VMLINUX_PATH="$path"
            break
        fi
    done
    
    if [ -z "$VMLINUX_PATH" ]; then
        echo "Could not find vmlinux. Trying to install kernel debug symbols..."
        sudo apt install -y linux-image-$KERNEL_RELEASE-dbg || {
            echo "Debug symbols not available. Trying to extract from kernel image..."
            if [ -f "/boot/vmlinuz-$KERNEL_RELEASE" ]; then
                # Try to extract BTF from kernel image if it exists
                if [ -e /sys/kernel/btf/vmlinux ]; then
                    sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
                    echo "Generated BTF header in $TEMP_DIR/vmlinux.h"
                else
                    echo "ERROR: No BTF information available in the kernel."
                    echo "You may need to install a kernel with BTF support."
                fi
            else
                echo "ERROR: Could not find kernel image to extract BTF information."
                echo "You may need to install the linux-image-$(uname -r) package."
                exit 1
            fi
        }
        
        # Check again for vmlinux after installing debug symbols
        for path in /boot/vmlinux-$KERNEL_RELEASE /usr/lib/debug/boot/vmlinux-$KERNEL_RELEASE; do
            if [ -f "$path" ]; then
                VMLINUX_PATH="$path"
                break
            fi
        done
    fi
    
    if [ -n "$VMLINUX_PATH" ]; then
        echo "Found vmlinux at $VMLINUX_PATH"
        # Generate BTF file
        sudo pahole -J $VMLINUX_PATH
        echo "Generated BTF information using pahole"
    fi
    
    # Clean up
    cd -
    rm -rf $TEMP_DIR
fi

# Check if BTF is now available
if [ -e /sys/kernel/btf/vmlinux ]; then
    echo "SUCCESS: BTF support is now available!"
else
    echo "WARNING: BTF support could not be enabled automatically."
    echo "This might be due to your kernel not having BTF support compiled in."
    
    # Try to install a newer kernel with BTF support
    echo "Would you like to install the latest HWE kernel which may have better BTF support? (y/n)"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        echo "Installing latest HWE kernel..."
        sudo apt install -y linux-image-generic-hwe-24.04 linux-headers-generic-hwe-24.04
        echo "Kernel installed. Please reboot your system and run this script again."
        exit 0
    else
        echo "Consider using the simplified XDP program that doesn't require BTF."
    fi
fi

echo "You may need to reboot your system for all changes to take effect."
