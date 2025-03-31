#!/bin/bash
# Script to install the latest libbpf version

set -e

echo "Installing dependencies for libbpf..."
sudo apt-get update
sudo apt-get install -y build-essential git pkg-config libelf-dev clang llvm

# Remove existing libbpf directory if it exists
if [ -d "libbpf" ]; then
    echo "Removing existing libbpf directory..."
    rm -rf libbpf
fi

echo "Cloning libbpf repository..."
git clone https://github.com/libbpf/libbpf.git
cd libbpf

echo "Building and installing libbpf..."
cd src
# Build both static and shared libraries
make

# Install to standard system locations
sudo make install

# Install pkg-config file for easier dependency management
sudo mkdir -p /usr/local/lib/pkgconfig
sudo cp libbpf.pc /usr/local/lib/pkgconfig/

# Update library cache
sudo ldconfig

echo "libbpf installed successfully!"
echo "Verifying installation..."

# Check if pkg-config can find libbpf
if pkg-config --exists libbpf; then
    echo "pkg-config verification: OK"
    echo "libbpf version: $(pkg-config --modversion libbpf)"
else
    echo "Warning: pkg-config cannot find libbpf"
fi

# Check if libraries are installed
if [ -f /usr/local/lib/libbpf.so ] || [ -f /usr/local/lib64/libbpf.so ]; then
    echo "Library installation: OK"
else
    echo "Warning: libbpf.so not found in expected locations"
fi

# Clean up
cd ../../
rm -rf libbpf

echo "Installation complete!"
