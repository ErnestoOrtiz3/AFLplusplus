#!/usr/bin/env python3

import sys
import os
import re
import glob
import csv
from collections import defaultdict
import matplotlib.pyplot as plt
from datetime import datetime

def parse_fuzzer_stats(directory):
    """Parse fuzzer_stats files from all instances in the given directory."""
    stats = {}
    for instance_dir in os.listdir(directory):
        instance_path = os.path.join(directory, instance_dir)
        if os.path.isdir(instance_path):
            stats_file = os.path.join(instance_path, "fuzzer_stats")
            if os.path.isfile(stats_file):
                instance_stats = {}
                with open(stats_file, 'r') as f:
                    for line in f:
                        if ':' in line:
                            key, value = line.strip().split(':', 1)
                            instance_stats[key.strip()] = value.strip()
                stats[instance_dir] = instance_stats
    return stats

def parse_boost_stats(stats_dir):
    boost_data = defaultdict(list)
    
    # Find all stats files
    stats_files = sorted(glob.glob(os.path.join(stats_dir, "custom", "stats_*.csv")))
    
    for file_path in stats_files:
        try:
            with open(file_path, 'r') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    pid = row['pid']
                    if pid and int(pid) > 0:  # Valid PID
                        boost_data[pid].append({
                            'timestamp': int(row['timestamp']),
                            'total_boost_time': int(row['total_boost_time']),
                            'is_boosted': int(row['is_boosted'])
                        })
        except Exception as e:
            print(f"Error parsing {file_path}: {e}")
    
    return boost_data

def generate_report(custom_dir, EEVDF_dir, stats_dir):
    # Parse fuzzer stats
    custom_stats = parse_fuzzer_stats(custom_dir)
    EEVDF_stats = parse_fuzzer_stats(EEVDF_dir)
    
    
    # Check if we have any stats to report
    if not custom_stats and not EEVDF_stats:
        return "No fuzzer stats found in either directory."

    # Generate report
    report = []
    report.append("=== AFL++ Scheduler Comparison Report ===\n")
    
    # Overall comparison
    report.append("== Overall Performance ==")
    
    # Calculate totals with safe defaults
    custom_total_execs = sum(float(stats.get('execs_per_sec', 0)) for stats in custom_stats.values())
    EEVDF_total_execs = sum(float(stats.get('execs_per_sec', 0)) for stats in EEVDF_stats.values())
    
    # Use corpus_count instead of paths_total
    custom_total_paths = sum(int(stats.get('corpus_count', 0)) for stats in custom_stats.values())
    EEVDF_total_paths = sum(int(stats.get('corpus_count', 0)) for stats in EEVDF_stats.values())
    
    # Use saved_crashes instead of unique_crashes
    custom_total_crashes = sum(int(stats.get('saved_crashes', 0)) for stats in custom_stats.values())
    EEVDF_total_crashes = sum(int(stats.get('saved_crashes', 0)) for stats in EEVDF_stats.values())
    
    # Safe division to avoid division by zero
    execs_diff = ((custom_total_execs / max(EEVDF_total_execs, 1)) - 1) * 100 if EEVDF_total_execs > 0 else 0
    paths_diff = ((custom_total_paths / max(EEVDF_total_paths, 1)) - 1) * 100 if EEVDF_total_paths > 0 else 0
    crashes_diff = ((custom_total_crashes / max(EEVDF_total_crashes, 1)) - 1) * 100 if EEVDF_total_crashes > 0 else 0
    
    report.append(f"Total executions/sec: Custom={custom_total_execs:.2f}, EEVDF={EEVDF_total_execs:.2f}, Diff={execs_diff:.2f}%")
    report.append(f"Total paths found: Custom={custom_total_paths}, EEVDF={EEVDF_total_paths}, Diff={paths_diff:.2f}%")
    report.append(f"Total crashes found: Custom={custom_total_crashes}, EEVDF={EEVDF_total_crashes}, Diff={crashes_diff:.2f}%")
    
    # Add additional metrics if available (percentage differences)
    try:
        custom_total_execs_done = sum(int(stats.get('execs_done', 0)) for stats in custom_stats.values())
        EEVDF_total_execs_done = sum(int(stats.get('execs_done', 0)) for stats in EEVDF_stats.values())
        execs_done_diff = ((custom_total_execs_done / max(EEVDF_total_execs_done, 1)) - 1) * 100 if EEVDF_total_execs_done > 0 else 0
        report.append(f"Total executions done: Custom={custom_total_execs_done}, EEVDF={EEVDF_total_execs_done}, Diff={execs_done_diff:.2f}%")
    except (ValueError, TypeError):
        pass
    
    try:
        custom_total_edges = sum(int(stats.get('edges_found', 0)) for stats in custom_stats.values())
        EEVDF_total_edges = sum(int(stats.get('edges_found', 0)) for stats in EEVDF_stats.values())
        edges_diff = ((custom_total_edges / max(EEVDF_total_edges, 1)) - 1) * 100 if EEVDF_total_edges > 0 else 0
        report.append(f"Total edges found: Custom={custom_total_edges}, EEVDF={EEVDF_total_edges}, Diff={edges_diff:.2f}%")
    except (ValueError, TypeError):
        pass
    
    try:
        # Calculate average bitmap coverage
        custom_bitmap_values = [float(stats.get('bitmap_cvg', '0%').replace('%', '')) for stats in custom_stats.values() if 'bitmap_cvg' in stats]
        EEVDF_bitmap_values = [float(stats.get('bitmap_cvg', '0%').replace('%', '')) for stats in EEVDF_stats.values() if 'bitmap_cvg' in stats]
        
        custom_total_bitmap_cvg = sum(custom_bitmap_values) / max(len(custom_bitmap_values), 1)
        EEVDF_total_bitmap_cvg = sum(EEVDF_bitmap_values) / max(len(EEVDF_bitmap_values), 1)
        
        bitmap_cvg_diff = custom_total_bitmap_cvg - EEVDF_total_bitmap_cvg
        report.append(f"Average bitmap coverage: Custom={custom_total_bitmap_cvg:.2f}%, EEVDF={EEVDF_total_bitmap_cvg:.2f}%, Diff={bitmap_cvg_diff:.2f}pp")
    except (ValueError, TypeError):
        pass
    
    # Instance comparison
    report.append("\n== Instance Performance ==")
    
    all_instances = sorted(set(list(custom_stats.keys()) + list(EEVDF_stats.keys())))
    
    for instance in all_instances:
        report.append(f"\n=== {instance} ===")
        
        if instance in custom_stats and instance in EEVDF_stats:
            # Basic metrics
            custom_execs = float(custom_stats[instance].get('execs_per_sec', 0))
            EEVDF_execs = float(EEVDF_stats[instance].get('execs_per_sec', 0))
            
            # Use corpus_count instead of paths_total
            custom_paths = int(custom_stats[instance].get('corpus_count', 0))
            EEVDF_paths = int(EEVDF_stats[instance].get('corpus_count', 0))
            
            # Use saved_crashes instead of unique_crashes
            custom_crashes = int(custom_stats[instance].get('saved_crashes', 0))
            EEVDF_crashes = int(EEVDF_stats[instance].get('saved_crashes', 0))
            
            # Safe division to avoid division by zero
            execs_diff = ((custom_execs / max(EEVDF_execs, 1)) - 1) * 100 if EEVDF_execs > 0 else 0
            paths_diff = ((custom_paths / max(EEVDF_paths, 1)) - 1) * 100 if EEVDF_paths > 0 else 0
            crashes_diff = ((custom_crashes / max(EEVDF_crashes, 1)) - 1) * 100 if EEVDF_crashes > 0 else 0
            
            report.append(f"Executions/sec: Custom={custom_execs:.2f}, EEVDF={EEVDF_execs:.2f}, Diff={execs_diff:.2f}%")
            report.append(f"Paths found: Custom={custom_paths}, EEVDF={EEVDF_paths}, Diff={paths_diff:.2f}%")
            report.append(f"Crashes found: Custom={custom_crashes}, EEVDF={EEVDF_crashes}, Diff={crashes_diff:.2f}%")
            
            # Additional metrics if available
            if 'cycles_done' in custom_stats[instance] and 'cycles_done' in EEVDF_stats[instance]:
                custom_cycles = float(custom_stats[instance].get('cycles_done', 0))
                EEVDF_cycles = float(EEVDF_stats[instance].get('cycles_done', 0))
                cycles_diff = ((custom_cycles / max(EEVDF_cycles, 1)) - 1) * 100 if EEVDF_cycles > 0 else 0
                report.append(f"Queue cycles: Custom={custom_cycles:.2f}, EEVDF={EEVDF_cycles:.2f}, Diff={cycles_diff:.2f}%")
            if 'execs_done' in custom_stats[instance] and 'execs_done' in EEVDF_stats[instance]:
                custom_execs_done = int(custom_stats[instance].get('execs_done', 0))
                EEVDF_execs_done = int(EEVDF_stats[instance].get('execs_done', 0))
                execs_done_diff = ((custom_execs_done / max(EEVDF_execs_done, 1)) - 1) * 100 if EEVDF_execs_done > 0 else 0
                report.append(f"Total executions: Custom={custom_execs_done}, EEVDF={EEVDF_execs_done}, Diff={execs_done_diff:.2f}%")
            
            if 'edges_found' in custom_stats[instance] and 'edges_found' in EEVDF_stats[instance]:
                custom_edges = int(custom_stats[instance].get('edges_found', 0))
                EEVDF_edges = int(EEVDF_stats[instance].get('edges_found', 0))
                edges_diff = ((custom_edges / max(EEVDF_edges, 1)) - 1) * 100 if EEVDF_edges > 0 else 0
                report.append(f"Edges found: Custom={custom_edges}, EEVDF={EEVDF_edges}, Diff={edges_diff:.2f}%")
            
            if 'bitmap_cvg' in custom_stats[instance] and 'bitmap_cvg' in EEVDF_stats[instance]:
                custom_bitmap_cvg = float(custom_stats[instance].get('bitmap_cvg', '0%').replace('%', ''))
                EEVDF_bitmap_cvg = float(EEVDF_stats[instance].get('bitmap_cvg', '0%').replace('%', ''))
                bitmap_cvg_diff = custom_bitmap_cvg - EEVDF_bitmap_cvg
                report.append(f"Bitmap coverage: Custom={custom_bitmap_cvg:.2f}%, EEVDF={EEVDF_bitmap_cvg:.2f}%, Diff={bitmap_cvg_diff:.2f}pp")
            
            if 'stability' in custom_stats[instance] and 'stability' in EEVDF_stats[instance]:
                custom_stability = float(custom_stats[instance].get('stability', '0%').replace('%', ''))
                EEVDF_stability = float(EEVDF_stats[instance].get('stability', '0%').replace('%', ''))
                stability_diff = custom_stability - EEVDF_stability
                report.append(f"Stability: Custom={custom_stability:.2f}%, EEVDF={EEVDF_stability:.2f}%, Diff={stability_diff:.2f}pp")
        else:
            report.append("Instance not present in both test runs")
    
    # Return the report as a string
    return "\n".join(report)

            
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <custom_scheduler_dir> <EEVDF_scheduler_dir> <stats_dir>")
        sys.exit(1)
    
    custom_dir = sys.argv[1]
    EEVDF_dir = sys.argv[2]
    stats_dir = sys.argv[3]
    
    report = generate_report(custom_dir, EEVDF_dir, stats_dir)
    print(report)
    
    # Generate plots if matplotlib is available
    try:
        # Create performance comparison chart
        custom_stats = parse_fuzzer_stats(custom_dir)
        EEVDF_stats = parse_fuzzer_stats(EEVDF_dir)
        
        instances = sorted(set(list(custom_stats.keys()) + list(EEVDF_stats.keys())))
        custom_execs = [float(custom_stats.get(i, {}).get('execs_per_sec', 0)) for i in instances]
        EEVDF_execs = [float(EEVDF_stats.get(i, {}).get('execs_per_sec', 0)) for i in instances]
        
        plt.figure(figsize=(10, 6))
        x = range(len(instances))
        width = 0.35
        
        plt.bar([i - width/2 for i in x], custom_execs, width, label='Custom Scheduler')
        plt.bar([i + width/2 for i in x], EEVDF_execs, width, label='EEVDF Scheduler')
        
        plt.xlabel('Instance')
        plt.ylabel('Executions per Second')
        plt.title('Performance Comparison: Custom vs EEVDF Scheduler')
        plt.xticks(x, instances)
        plt.legend()
        
        plt.savefig(os.path.join(os.path.dirname(custom_dir), 'performance_comparison.png'))
    except ImportError:
        print("Matplotlib not available, skipping plot generation")
