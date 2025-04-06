#!/usr/bin/env python3
"""
AFL++ Priority Daemon

This script monitors AFL++ fuzzer processes with scheduler feedback enabled
and adjusts their process priorities based on their performance metrics.
"""

import os
import sys
import time
import signal
import struct
import subprocess
import csv
import glob
from datetime import datetime
import ctypes
import mmap
import re

# Structure that matches the AFL++ scheduler_feedback_t
class SchedulerFeedback(ctypes.Structure):
    _fields_ = [
        ("pid", ctypes.c_int),
        ("last_update_time", ctypes.c_ulonglong),
        ("new_edges_found", ctypes.c_uint),
        ("total_edges_found", ctypes.c_uint),
        ("execs_per_sec", ctypes.c_uint),
        ("paths_found", ctypes.c_uint),
        ("unique_crashes", ctypes.c_uint),
        ("unique_hangs", ctypes.c_uint),
        ("queue_cycle", ctypes.c_uint),
        ("pending_favs", ctypes.c_uint),
        ("performance_score", ctypes.c_ubyte),
        ("reserved", ctypes.c_ubyte * 3)
    ]

class AFLPriorityDaemon:
    def __init__(self, metrics_dir="./scheduler_metrics", interval=1):
        self.metrics_dir = metrics_dir
        self.interval = interval
        self.running = True
        self.metrics_log = None
        self.fuzzer_stats = {}
        self.shm_addrs = {}

        # Create metrics directory if it doesn't exist
        os.makedirs(metrics_dir, exist_ok=True)

        # Initialize metrics log
        self.metrics_log_path = os.path.join(metrics_dir, "metrics_log.csv")
        self.metrics_log = open(self.metrics_log_path, "w")
        self.metrics_writer = csv.writer(self.metrics_log)
        self.metrics_writer.writerow([
            "timestamp", "pid", "new_edges", "total_edges", "execs_per_sec",
            "paths_found", "unique_crashes", "unique_hangs", "queue_cycle",
            "pending_favs", "performance_score", "nice_value"
        ])
        self.metrics_log.flush()

        # Set up signal handlers
        signal.signal(signal.SIGINT, self.handle_signal)
        signal.signal(signal.SIGTERM, self.handle_signal)

    def handle_signal(self, signum, frame):
        print(f"Received signal {signum}, shutting down...")
        self.running = False

    def calculate_nice_value(self, feedback):
        """Calculate process nice value based on performance metrics"""
        # Default nice value (lower is higher priority, -20 to 19)
        base_nice = 0
        adjustments = []

        # Adjust based on performance metrics
        if feedback.new_edges_found > 0:
            # Finding new edges is good, give higher priority
            adjustment = min(feedback.new_edges_found, 10)
            base_nice -= adjustment
            adjustments.append(f"new edges: {feedback.new_edges_found} -> -{adjustment}")

        if feedback.unique_crashes > 0:
            # Finding crashes is good, give higher priority
            base_nice -= 5
            adjustments.append(f"crashes: {feedback.unique_crashes} -> -5")

        if feedback.execs_per_sec > 500:
            # High execution speed is good, give higher priority
            base_nice -= 2
            adjustments.append(f"high exec speed: {feedback.execs_per_sec} -> -2")

        if feedback.performance_score > 50:
            # High performance score is good, give higher priority
            base_nice -= 3
            adjustments.append(f"high performance score: {feedback.performance_score} -> -3")

        # Ensure nice value is within valid range (-20 to 19)
        nice_value = max(-20, min(19, base_nice))

        if adjustments:
            print(f"PID {feedback.pid}: Adjusting priority based on {', '.join(adjustments)}. Final nice value: {nice_value}")

        return nice_value

    def set_process_priority(self, pid, nice_value):
        """Set process priority using renice"""
        try:
            subprocess.run(["renice", "-n", str(nice_value), "-p", str(pid)],
                          check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return True
        except subprocess.CalledProcessError:
            print(f"Failed to set priority for PID {pid}")
            return False

    def log_metrics(self, pid, feedback, nice_value):
        """Log metrics to CSV file"""
        if self.metrics_log:
            self.metrics_writer.writerow([
                datetime.now().timestamp(),
                pid,
                feedback.new_edges_found,
                feedback.total_edges_found,
                feedback.execs_per_sec,
                feedback.paths_found,
                feedback.unique_crashes,
                feedback.unique_hangs,
                feedback.queue_cycle,
                feedback.pending_favs,
                feedback.performance_score,
                nice_value
            ])
            self.metrics_log.flush()

    def find_feedback_files(self):
        """Find all scheduler_feedback.txt files in the system"""
        feedback_files = []

        # Look for AFL++ output directories
        output_dirs = []
        output_dirs.extend(glob.glob("/*/output_*"))
        output_dirs.extend(glob.glob("/home/*/output_*"))
        output_dirs.extend(glob.glob("./output_*"))
        output_dirs.extend(glob.glob("../output_*"))

        # Also look for multi-instance output directories
        output_dirs.extend(glob.glob("./output_comparison/*"))
        output_dirs.extend(glob.glob("./output_multi"))

        for output_dir in output_dirs:
            # Check for scheduler_feedback.txt directly in the output directory
            feedback_path = os.path.join(output_dir, "scheduler_feedback.txt")
            if os.path.exists(feedback_path):
                feedback_files.append(feedback_path)
                print(f"Found feedback file: {feedback_path}")

            # Check in standard subdirectories
            for subdir in ["default", "scheduler"]:
                feedback_path = os.path.join(output_dir, subdir, "scheduler_feedback.txt")
                if os.path.exists(feedback_path):
                    feedback_files.append(feedback_path)
                    print(f"Found feedback file: {feedback_path}")

            # Check in fuzzer instance subdirectories (fuzzer0, fuzzer1, etc.)
            fuzzer_dirs = glob.glob(os.path.join(output_dir, "fuzzer*"))
            for fuzzer_dir in fuzzer_dirs:
                if os.path.isdir(fuzzer_dir):
                    feedback_path = os.path.join(fuzzer_dir, "scheduler_feedback.txt")
                    if os.path.exists(feedback_path):
                        feedback_files.append(feedback_path)
                        print(f"Found feedback file: {feedback_path}")

        if not feedback_files:
            print("No feedback files found. Make sure AFL++ instances are running with scheduler feedback enabled.")
        else:
            print(f"Found {len(feedback_files)} feedback files.")

        return feedback_files

    def scan_for_fuzzers(self):
        """Scan for AFL++ fuzzer processes with scheduler feedback"""
        # Find all scheduler_feedback.txt files
        feedback_files = self.find_feedback_files()

        for feedback_path in feedback_files:
            try:
                # Read shared memory ID from feedback file
                try:
                    with open(feedback_path, "r") as f:
                        content = f.read().strip()
                        print(f"Feedback file content: '{content}'")
                        shm_id = int(content)
                except ValueError as e:
                    print(f"Error parsing shared memory ID from {feedback_path}: {e}")
                    continue

                # Attach to shared memory
                try:
                    # Try to attach using shmat via ctypes
                    libc = ctypes.CDLL("libc.so.6")
                    shmat = libc.shmat
                    shmat.argtypes = [ctypes.c_int, ctypes.c_void_p, ctypes.c_int]
                    shmat.restype = ctypes.c_void_p

                    shmaddr = shmat(shm_id, None, 0)
                    if shmaddr == -1:
                        print(f"Failed to attach to shared memory with ID {shm_id}")
                        continue

                    # Create a ctypes buffer from the shared memory
                    buffer = (ctypes.c_char * ctypes.sizeof(SchedulerFeedback)).from_address(shmaddr)
                    feedback = SchedulerFeedback.from_buffer_copy(buffer)
                    print(f"Successfully attached to shared memory with ID {shm_id} using ctypes")

                    # Store the shmaddr for later detachment
                    self.shm_addrs[shm_id] = shmaddr
                except Exception as e:
                    print(f"Error attaching to shared memory: {e}")
                    continue

                # Calculate nice value
                nice_value = self.calculate_nice_value(feedback)

                # Set process priority
                if self.set_process_priority(feedback.pid, nice_value):
                    print(f"Updated priority for PID {feedback.pid} to {nice_value} "
                          f"(score: {feedback.performance_score}, "
                          f"new edges: {feedback.new_edges_found})")

                # Log metrics
                self.log_metrics(feedback.pid, feedback, nice_value)

                # Detach from shared memory
                try:
                    if shm_id in self.shm_addrs:
                        # Using ctypes
                        libc = ctypes.CDLL("libc.so.6")
                        shmdt = libc.shmdt
                        shmdt.argtypes = [ctypes.c_void_p]
                        shmdt.restype = ctypes.c_int

                        result = shmdt(self.shm_addrs[shm_id])
                        if result == -1:
                            print(f"Failed to detach from shared memory with ID {shm_id}")
                        else:
                            print(f"Successfully detached from shared memory with ID {shm_id}")
                            del self.shm_addrs[shm_id]
                except Exception as e:
                    print(f"Error detaching from shared memory: {e}")

            except Exception as e:
                print(f"Error processing {feedback_path}: {e}")

    def cleanup(self):
        """Clean up resources"""
        # Detach from all shared memory segments
        if hasattr(self, 'shm_addrs') and self.shm_addrs:
            libc = ctypes.CDLL("libc.so.6")
            shmdt = libc.shmdt
            shmdt.argtypes = [ctypes.c_void_p]
            shmdt.restype = ctypes.c_int

            for shm_id, shmaddr in list(self.shm_addrs.items()):
                try:
                    result = shmdt(shmaddr)
                    if result == -1:
                        print(f"Failed to detach from shared memory with ID {shm_id}")
                    else:
                        print(f"Successfully detached from shared memory with ID {shm_id}")
                        del self.shm_addrs[shm_id]
                except Exception as e:
                    print(f"Error detaching from shared memory: {e}")

        # Close metrics log
        if self.metrics_log:
            self.metrics_log.close()

    def run(self):
        """Main loop"""
        print(f"AFL++ Priority Daemon started, logging to {self.metrics_log_path}")

        try:
            while self.running:
                self.scan_for_fuzzers()
                time.sleep(self.interval)
        except KeyboardInterrupt:
            print("Received keyboard interrupt, shutting down...")
        except Exception as e:
            print(f"Error in main loop: {e}")
        finally:
            print("AFL++ Priority Daemon shutting down")
            self.cleanup()

if __name__ == "__main__":
    metrics_dir = "./scheduler_metrics"
    interval = 1

    # Parse command line arguments
    if len(sys.argv) > 1:
        metrics_dir = sys.argv[1]
    if len(sys.argv) > 2:
        interval = float(sys.argv[2])

    daemon = AFLPriorityDaemon(metrics_dir, interval)
    daemon.run()
