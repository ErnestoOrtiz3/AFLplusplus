#!/usr/bin/env python3
"""
Extract statistics from AFL++ output directory for the custom scheduler.
"""

import sys
import os
import re
import glob
from pathlib import Path

def extract_stats(afl_dir):
    """Extract key statistics from AFL++ output directory."""
    stats = {
        'custom_execs': 0.0,
        'custom_paths': 0,
        'custom_crashes': 0,
        'custom_edges': 0,
        'custom_bitmap': 0.0
    }
    
    print(f"DEBUG: Extracting stats from {afl_dir}")
    
    # Process each fuzzer's stats
    total_execs_per_sec = 0.0
    total_paths = 0
    total_crashes = 0
    total_edges = 0
    fuzzer_count = 0
    
    stats_files = glob.glob(f"{afl_dir}/*/fuzzer_stats")
    print(f"DEBUG: Found {len(stats_files)} fuzzer_stats files")
    
    for stats_file in stats_files:
        print(f"DEBUG: Processing {stats_file}")
        with open(stats_file, 'r') as f:
            content = f.read()
            
            # Extract executions per second
            execs_match = re.search(r'execs_per_sec\s+:\s+([\d.]+)', content)
            if execs_match:
                execs_value = float(execs_match.group(1))
                print(f"DEBUG: Found execs_per_sec = {execs_value}")
                total_execs_per_sec += execs_value
                
                # Extract paths (corpus_count)
                paths_match = re.search(r'corpus_count\s+:\s+(\d+)', content)
                if paths_match:
                    paths_value = int(paths_match.group(1))
                    print(f"DEBUG: Found corpus_count = {paths_value}")
                    total_paths += paths_value
                
                # Extract crashes
                crashes_match = re.search(r'saved_crashes\s+:\s+(\d+)', content)
                if crashes_match:
                    crashes_value = int(crashes_match.group(1))
                    print(f"DEBUG: Found saved_crashes = {crashes_value}")
                    total_crashes += crashes_value
                
                # Extract edges
                edges_match = re.search(r'edges_found\s+:\s+(\d+)', content)
                if edges_match:
                    edges_value = int(edges_match.group(1))
                    print(f"DEBUG: Found edges_found = {edges_value}")
                    total_edges += edges_value
                
                # Extract bitmap coverage
                bitmap_match = re.search(r'bitmap_cvg\s+:\s+([\d.]+)%', content)
                if bitmap_match:
                    bitmap_value = float(bitmap_match.group(1))
                    print(f"DEBUG: Found bitmap_cvg = {bitmap_value}%")
                    stats['custom_bitmap'] += bitmap_value
                
                fuzzer_count += 1
            else:
                print(f"DEBUG: Could not find execs_per_sec in {stats_file}")
    
    if fuzzer_count > 0:
        stats['custom_execs'] = total_execs_per_sec
        stats['custom_paths'] = total_paths
        stats['custom_crashes'] = total_crashes
        stats['custom_edges'] = total_edges
        stats['custom_bitmap'] = stats['custom_bitmap'] / fuzzer_count  # Average bitmap coverage
        
        print(f"DEBUG: Total execs_per_sec = {total_execs_per_sec}")
        print(f"DEBUG: Total paths = {total_paths}")
        print(f"DEBUG: Total crashes = {total_crashes}")
        print(f"DEBUG: Total edges = {total_edges}")
        print(f"DEBUG: Average bitmap coverage = {stats['custom_bitmap']}%")
    
    print(f"DEBUG: Final stats: {stats}")
    return stats

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <afl_output_dir>")
        sys.exit(1)
    
    afl_dir = sys.argv[1]
    if not os.path.isdir(afl_dir):
        print(f"Error: {afl_dir} is not a directory")
        sys.exit(1)
    
    stats = extract_stats(afl_dir)
    
    # Print stats in the format expected by the parser
    print("Custom Scheduler Performance:")
    print(f"Total executions/sec: Custom={stats['custom_execs']:.2f}")
    print(f"Total paths found: Custom={stats['custom_paths']}")
    print(f"Total crashes found: Custom={stats['custom_crashes']}")
    print(f"Total edges found: Custom={stats['custom_edges']}")
    print(f"Average bitmap coverage: Custom={stats['custom_bitmap']:.2f}%")

if __name__ == "__main__":
    main()
