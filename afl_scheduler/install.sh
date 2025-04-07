#!/bin/bash
#
# Installation script for AFL++ CPU Scheduler
#

# Check if running as root
if [ "$EUID" -ne 0 ]; then
  echo "Please run as root"
  exit 1
fi

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Build the scheduler
echo "Building AFL++ CPU Scheduler..."
cd "$SCRIPT_DIR"
make clean
make

if [ $? -ne 0 ]; then
  echo "Build failed. Please check the error messages above."
  exit 1
fi

# Install binaries
echo "Installing binaries..."
install -m 755 afl_monitor /usr/local/bin/
install -m 755 afl_sched /usr/local/bin/
install -m 755 afl_sched_ctl.sh /usr/local/bin/

# Install systemd service
echo "Installing systemd service..."
install -m 644 afl-scheduler.service /etc/systemd/system/
systemctl daemon-reload

echo ""
echo "Installation complete!"
echo ""
echo "To start the scheduler:"
echo "  sudo systemctl start afl-scheduler"
echo ""
echo "To enable automatic start at boot:"
echo "  sudo systemctl enable afl-scheduler"
echo ""
echo "To check status:"
echo "  sudo systemctl status afl-scheduler"
echo ""
echo "To stop the scheduler:"
echo "  sudo systemctl stop afl-scheduler"
echo ""
echo "Alternatively, you can use the control script directly:"
echo "  sudo afl_sched_ctl.sh [start|stop|status]"
echo ""

exit 0
