#!/usr/bin/env python3
"""
AFL++ Feedback-Guided CPU Scheduler Metrics Visualization
--------------------------------------------------------

This script generates visualizations from the metrics collected by the
scheduler daemon to help evaluate its effectiveness.
"""

import os
import sys
import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.dates as mdates
import numpy as np
from datetime import datetime

def parse_timestamp(ts):
    """Parse timestamp from the metrics log."""
    return datetime.strptime(ts, '%Y-%m-%d %H:%M:%S')

def load_metrics_log(metrics_dir):
    """Load the metrics log file into a pandas DataFrame."""
    log_path = os.path.join(metrics_dir, 'metrics_log.csv')
    if not os.path.exists(log_path):
        print(f"Error: Metrics log file not found at {log_path}")
        return None
    
    # Load the CSV file
    df = pd.read_csv(log_path)
    
    # Convert timestamp to datetime
    df['timestamp'] = df['timestamp'].apply(parse_timestamp)
    
    # Filter out REMOVED entries
    df = df[df['total_edges'] != 'REMOVED']
    df['total_edges'] = df['total_edges'].astype(int)
    
    return df

def plot_edge_coverage(df, output_dir):
    """Plot edge coverage over time for each fuzzer."""
    if df is None or df.empty:
        return
    
    plt.figure(figsize=(12, 8))
    
    # Group by PID
    for pid, group in df.groupby('pid'):
        # Sort by timestamp
        group = group.sort_values('timestamp')
        
        # Plot total edges
        plt.plot(group['timestamp'], group['total_edges'], 
                 label=f'PID {pid}', marker='o', markersize=3)
    
    plt.title('Edge Coverage Over Time')
    plt.xlabel('Time')
    plt.ylabel('Total Edges')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Format x-axis to show dates nicely
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.gcf().autofmt_xdate()
    
    # Save the plot
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'edge_coverage.png'))
    plt.close()

def plot_edge_discovery_rate(df, output_dir):
    """Plot edge discovery rate over time for each fuzzer."""
    if df is None or df.empty:
        return
    
    plt.figure(figsize=(12, 8))
    
    # Group by PID
    for pid, group in df.groupby('pid'):
        # Sort by timestamp
        group = group.sort_values('timestamp')
        
        # Calculate cumulative new edges
        group['cumulative_new_edges'] = group['new_edges'].cumsum()
        
        # Plot cumulative new edges
        plt.plot(group['timestamp'], group['cumulative_new_edges'], 
                 label=f'PID {pid}', marker='o', markersize=3)
    
    plt.title('Cumulative New Edges Over Time')
    plt.xlabel('Time')
    plt.ylabel('Cumulative New Edges')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Format x-axis to show dates nicely
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.gcf().autofmt_xdate()
    
    # Save the plot
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'edge_discovery_rate.png'))
    plt.close()

def plot_weight_vs_performance(df, output_dir):
    """Plot the relationship between assigned weight and performance."""
    if df is None or df.empty:
        return
    
    plt.figure(figsize=(12, 8))
    
    # Group by PID
    for pid, group in df.groupby('pid'):
        # Filter out rows with zero weight
        group = group[group['weight'] > 0]
        
        if len(group) < 2:
            continue
        
        # Calculate moving average of new edges (window size 5)
        window_size = min(5, len(group))
        group['edge_rate_ma'] = group['new_edges'].rolling(window=window_size).mean()
        
        # Plot weight vs edge rate
        plt.scatter(group['weight'], group['edge_rate_ma'], 
                   label=f'PID {pid}', alpha=0.7)
    
    plt.title('Weight vs Edge Discovery Rate')
    plt.xlabel('Assigned Weight')
    plt.ylabel('Edge Discovery Rate (Moving Avg)')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Save the plot
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'weight_vs_performance.png'))
    plt.close()

def plot_prioritization_effectiveness(df, output_dir):
    """Plot the effectiveness of prioritization decisions."""
    if df is None or df.empty:
        return
    
    plt.figure(figsize=(12, 8))
    
    # Calculate edge gain after prioritization
    prioritized = df[df['prioritized'] == 1]
    not_prioritized = df[df['prioritized'] == 0]
    
    # Group by PID
    prioritized_edges = prioritized.groupby('pid')['new_edges'].sum()
    not_prioritized_edges = not_prioritized.groupby('pid')['new_edges'].sum()
    
    # Count prioritizations
    prioritization_count = prioritized.groupby('pid').size()
    non_prioritization_count = not_prioritized.groupby('pid').size()
    
    # Calculate edges per decision
    prioritized_edges_per_decision = prioritized_edges / prioritization_count
    not_prioritized_edges_per_decision = not_prioritized_edges / non_prioritization_count
    
    # Prepare data for plotting
    pids = sorted(set(prioritized_edges.index) | set(not_prioritized_edges.index))
    p_edges = [prioritized_edges_per_decision.get(pid, 0) for pid in pids]
    np_edges = [not_prioritized_edges_per_decision.get(pid, 0) for pid in pids]
    
    # Set up bar positions
    x = np.arange(len(pids))
    width = 0.35
    
    # Create bars
    plt.bar(x - width/2, p_edges, width, label='Prioritized')
    plt.bar(x + width/2, np_edges, width, label='Not Prioritized')
    
    plt.title('Edge Discovery Rate: Prioritized vs Not Prioritized')
    plt.xlabel('Process ID')
    plt.ylabel('Edges per Decision')
    plt.xticks(x, [f'PID {pid}' for pid in pids])
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Save the plot
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'prioritization_effectiveness.png'))
    plt.close()

def plot_crash_discovery(df, output_dir):
    """Plot crash discovery over time for each fuzzer."""
    if df is None or df.empty:
        return
    
    plt.figure(figsize=(12, 8))
    
    # Group by PID
    for pid, group in df.groupby('pid'):
        # Sort by timestamp
        group = group.sort_values('timestamp')
        
        # Calculate cumulative new crashes
        group['cumulative_new_crashes'] = group['new_crashes'].cumsum()
        
        # Plot cumulative new crashes
        plt.plot(group['timestamp'], group['cumulative_new_crashes'], 
                 label=f'PID {pid}', marker='o', markersize=3)
    
    plt.title('Cumulative Crashes Over Time')
    plt.xlabel('Time')
    plt.ylabel('Cumulative Crashes')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Format x-axis to show dates nicely
    plt.gca().xaxis.set_major_formatter(mdates.DateFormatter('%H:%M:%S'))
    plt.gcf().autofmt_xdate()
    
    # Save the plot
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'crash_discovery.png'))
    plt.close()

def plot_weight_distribution(df, output_dir):
    """Plot the distribution of weights assigned to each fuzzer."""
    if df is None or df.empty:
        return
    
    plt.figure(figsize=(12, 8))
    
    # Group by PID
    for pid, group in df.groupby('pid'):
        # Filter out rows with zero weight
        group = group[group['weight'] > 0]
        
        if len(group) < 2:
            continue
        
        # Plot weight distribution
        plt.hist(group['weight'], bins=20, alpha=0.5, label=f'PID {pid}')
    
    plt.title('Distribution of Assigned Weights')
    plt.xlabel('Weight')
    plt.ylabel('Frequency')
    plt.legend()
    plt.grid(True, linestyle='--', alpha=0.7)
    
    # Save the plot
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'weight_distribution.png'))
    plt.close()

def generate_summary_report(df, metrics_dir, output_dir):
    """Generate a summary report of the metrics."""
    if df is None or df.empty:
        return
    
    # Create output file
    report_path = os.path.join(output_dir, 'metrics_summary.txt')
    with open(report_path, 'w') as f:
        f.write("AFL++ Scheduler Metrics Summary\n")
        f.write("==============================\n\n")
        
        # Time range
        start_time = df['timestamp'].min()
        end_time = df['timestamp'].max()
        duration = (end_time - start_time).total_seconds() / 3600  # hours
        
        f.write(f"Start time: {start_time}\n")
        f.write(f"End time: {end_time}\n")
        f.write(f"Duration: {duration:.2f} hours\n\n")
        
        # Process statistics
        pids = df['pid'].unique()
        f.write(f"Number of processes: {len(pids)}\n\n")
        
        f.write("Per-Process Statistics:\n")
        f.write("----------------------\n")
        
        for pid in pids:
            process_df = df[df['pid'] == pid]
            
            # Calculate statistics
            total_edges = process_df['total_edges'].max()
            total_new_edges = process_df['new_edges'].sum()
            total_crashes = process_df['new_crashes'].sum()
            prioritized_count = (process_df['prioritized'] == 1).sum()
            non_prioritized_count = (process_df['prioritized'] == 0).sum()
            prioritization_ratio = prioritized_count / len(process_df) if len(process_df) > 0 else 0
            
            # Edges gained during prioritization vs non-prioritization
            prioritized_edges = process_df[process_df['prioritized'] == 1]['new_edges'].sum()
            non_prioritized_edges = process_df[process_df['prioritized'] == 0]['new_edges'].sum()
            
            edges_per_prioritization = prioritized_edges / prioritized_count if prioritized_count > 0 else 0
            edges_per_non_prioritization = non_prioritized_edges / non_prioritized_count if non_prioritized_count > 0 else 0
            
            # Write statistics
            f.write(f"PID {pid}:\n")
            f.write(f"  Total edges: {total_edges}\n")
            f.write(f"  New edges found: {total_new_edges}\n")
            f.write(f"  Crashes found: {total_crashes}\n")
            f.write(f"  Times prioritized: {prioritized_count}\n")
            f.write(f"  Prioritization ratio: {prioritization_ratio:.2f}\n")
            f.write(f"  Edges per prioritization: {edges_per_prioritization:.2f}\n")
            f.write(f"  Edges per non-prioritization: {edges_per_non_prioritization:.2f}\n")
            
            # Calculate effectiveness ratio
            if edges_per_non_prioritization > 0:
                effectiveness_ratio = edges_per_prioritization / edges_per_non_prioritization
                f.write(f"  Effectiveness ratio: {effectiveness_ratio:.2f}\n")
                
                # Interpretation
                if effectiveness_ratio > 1.5:
                    f.write("  Interpretation: Prioritization is HIGHLY EFFECTIVE for this process\n")
                elif effectiveness_ratio > 1.0:
                    f.write("  Interpretation: Prioritization is EFFECTIVE for this process\n")
                elif effectiveness_ratio > 0.5:
                    f.write("  Interpretation: Prioritization is SOMEWHAT EFFECTIVE for this process\n")
                else:
                    f.write("  Interpretation: Prioritization is NOT EFFECTIVE for this process\n")
            
            f.write("\n")
        
        # Overall effectiveness
        total_prioritized_edges = df[df['prioritized'] == 1]['new_edges'].sum()
        total_non_prioritized_edges = df[df['prioritized'] == 0]['new_edges'].sum()
        
        total_prioritized_count = (df['prioritized'] == 1).sum()
        total_non_prioritized_count = (df['prioritized'] == 0).sum()
        
        overall_edges_per_prioritization = total_prioritized_edges / total_prioritized_count if total_prioritized_count > 0 else 0
        overall_edges_per_non_prioritization = total_non_prioritized_edges / total_non_prioritized_count if total_non_prioritized_count > 0 else 0
        
        f.write("Overall Effectiveness:\n")
        f.write("---------------------\n")
        f.write(f"Total edges found: {df['new_edges'].sum()}\n")
        f.write(f"Total crashes found: {df['new_crashes'].sum()}\n")
        f.write(f"Total prioritizations: {total_prioritized_count}\n")
        f.write(f"Overall edges per prioritization: {overall_edges_per_prioritization:.2f}\n")
        f.write(f"Overall edges per non-prioritization: {overall_edges_per_non_prioritization:.2f}\n")
        
        if overall_edges_per_non_prioritization > 0:
            overall_effectiveness_ratio = overall_edges_per_prioritization / overall_edges_per_non_prioritization
            f.write(f"Overall effectiveness ratio: {overall_effectiveness_ratio:.2f}\n")
            
            # Overall interpretation
            if overall_effectiveness_ratio > 1.5:
                f.write("Interpretation: The scheduler is HIGHLY EFFECTIVE at prioritizing productive fuzzers\n")
            elif overall_effectiveness_ratio > 1.0:
                f.write("Interpretation: The scheduler is EFFECTIVE at prioritizing productive fuzzers\n")
            elif overall_effectiveness_ratio > 0.5:
                f.write("Interpretation: The scheduler is SOMEWHAT EFFECTIVE at prioritizing productive fuzzers\n")
            else:
                f.write("Interpretation: The scheduler does not appear to be more effective than random scheduling\n")
    
    print(f"Generated summary report: {report_path}")

def main():
    if len(sys.argv) < 2:
        print("Usage: plot_metrics.py <metrics_directory> [output_directory]")
        sys.exit(1)
    
    metrics_dir = sys.argv[1]
    output_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(metrics_dir, 'plots')
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Load metrics log
    df = load_metrics_log(metrics_dir)
    if df is None:
        print("Failed to load metrics log")
        sys.exit(1)
    
    # Generate plots
    print("Generating plots...")
    plot_edge_coverage(df, output_dir)
    plot_edge_discovery_rate(df, output_dir)
    plot_weight_vs_performance(df, output_dir)
    plot_prioritization_effectiveness(df, output_dir)
    plot_crash_discovery(df, output_dir)
    plot_weight_distribution(df, output_dir)
    
    # Generate summary report
    print("Generating summary report...")
    generate_summary_report(df, metrics_dir, output_dir)
    
    print(f"All visualizations saved to {output_dir}")

if __name__ == "__main__":
    main()
