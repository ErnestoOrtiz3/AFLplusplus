#!/usr/bin/env python3
"""
Generate visualizations from AFL++ scheduler optimization results
"""

import json
import glob
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.colors import LinearSegmentedColormap
import matplotlib.gridspec as gridspec
from matplotlib.ticker import MaxNLocator

# Set style for plots
plt.style.use('ggplot')
plt.rcParams['figure.figsize'] = (12, 8)
plt.rcParams['font.size'] = 12

# Create output directory
output_dir = 'optimization_visualizations'
os.makedirs(output_dir, exist_ok=True)

def load_trial_data():
    """Load all trial data from JSON files"""
    all_trials = []
    for trial_file in glob.glob('optuna_results_*/trial_*.json'):
        with open(trial_file, 'r') as f:
            trial_data = json.load(f)
            all_trials.append(trial_data)
    
    # Sort by trial number
    all_trials.sort(key=lambda x: x['trial'])
    return all_trials

def create_dataframe(trials):
    """Convert trial data to pandas DataFrame"""
    data = []
    for trial in trials:
        row = {
            'trial': trial['trial'],
            'score': trial['score'],
            'boost_duration': trial['params']['boost_duration'],
            'boost_weight': trial['params']['boost_weight'],
            'boost_decay': trial['params']['boost_decay'],
            'slice_us': trial['params']['slice_us'],
            'slice_min_us': trial['params']['slice_min_us'],
            'paths_diff': trial['metrics']['paths_diff'],
            'crashes_diff': trial['metrics']['crashes_diff'],
            'edges_diff': trial['metrics']['edges_diff'],
            'bitmap_diff': trial['metrics']['bitmap_diff'],
            'execs_diff': trial['metrics']['execs_diff'],
            'custom_paths': trial['metrics']['custom_paths'],
            'cfs_paths': trial['metrics']['cfs_paths'],
            'custom_crashes': trial['metrics']['custom_crashes'],
            'cfs_crashes': trial['metrics']['cfs_crashes'],
            'custom_edges': trial['metrics']['custom_edges'],
            'cfs_edges': trial['metrics']['cfs_edges'],
            'custom_bitmap': trial['metrics']['custom_bitmap'],
            'cfs_bitmap': trial['metrics']['cfs_bitmap'],
            'custom_execs': trial['metrics']['custom_execs'],
            'cfs_execs': trial['metrics']['cfs_execs']
        }
        data.append(row)
    return pd.DataFrame(data)

def plot_optimization_history(df):
    """Plot optimization history"""
    plt.figure(figsize=(14, 8))
    
    # Sort by trial number for chronological view
    df_sorted = df.sort_values('trial')
    
    plt.plot(df_sorted['trial'], df_sorted['score'], 'o-', linewidth=2, markersize=8)
    plt.axhline(y=0, color='r', linestyle='--', alpha=0.5)
    
    # Highlight best trial
    best_trial = df.loc[df['score'].idxmax()]
    plt.scatter(best_trial['trial'], best_trial['score'], s=200, c='green', 
                marker='*', edgecolors='black', zorder=10, 
                label=f'Best Trial ({best_trial["trial"]})')
    
    plt.title('Optimization History', fontsize=16)
    plt.xlabel('Trial Number', fontsize=14)
    plt.ylabel('Score', fontsize=14)
    plt.grid(True, alpha=0.3)
    plt.legend(fontsize=12)
    
    # Add text annotation for best score
    plt.annotate(f'Best Score: {best_trial["score"]:.2f}', 
                 xy=(best_trial['trial'], best_trial['score']),
                 xytext=(10, 30), textcoords='offset points',
                 arrowprops=dict(arrowstyle='->', connectionstyle='arc3,rad=.2'))
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'optimization_history.png'), dpi=300)
    plt.close()

def plot_parameter_parallel(df):
    """Create parallel coordinates plot for parameters"""
    # Get top 5 trials by score
    top_df = df.nlargest(5, 'score')
    
    # Create a colormap for the scores
    norm = plt.Normalize(top_df['score'].min(), top_df['score'].max())
    colors = plt.cm.viridis(norm(top_df['score']))
    
    # Parameters to plot
    params = ['boost_duration', 'boost_weight', 'boost_decay', 'slice_us', 'slice_min_us']
    
    # Create figure
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Get parameter ranges for normalization
    ranges = {}
    for param in params:
        ranges[param] = (df[param].min(), df[param].max())
    
    # Plot each trial
    for i, (_, row) in enumerate(top_df.iterrows()):
        # Normalize parameters to [0, 1] for plotting
        points = []
        for j, param in enumerate(params):
            min_val, max_val = ranges[param]
            if max_val > min_val:
                normalized = (row[param] - min_val) / (max_val - min_val)
            else:
                normalized = 0.5
            points.append((j, normalized))
        
        # Plot line for this trial
        xs, ys = zip(*points)
        ax.plot(xs, ys, 'o-', linewidth=2, markersize=8, color=colors[i], 
                label=f'Trial {row["trial"]} (Score: {row["score"]:.2f})')
        
        # Add parameter values as text
        for j, param in enumerate(params):
            ax.annotate(f'{row[param]}', 
                       xy=(xs[j], ys[j]), 
                       xytext=(0, 10), 
                       textcoords='offset points',
                       ha='center', va='bottom',
                       fontsize=8)
    
    # Set up axes
    ax.set_xticks(range(len(params)))
    ax.set_xticklabels(params, rotation=45)
    ax.set_yticks([])
    ax.set_ylim(-0.1, 1.1)
    
    # Add parameter ranges
    for i, param in enumerate(params):
        min_val, max_val = ranges[param]
        ax.annotate(f'{min_val}', xy=(i, 0), xytext=(0, -20), 
                   textcoords='offset points', ha='center', va='top')
        ax.annotate(f'{max_val}', xy=(i, 1), xytext=(0, 10), 
                   textcoords='offset points', ha='center', va='bottom')
    
    plt.title('Parameter Values for Top 5 Trials', fontsize=16)
    plt.grid(False)
    plt.legend(loc='upper center', bbox_to_anchor=(0.5, -0.15), ncol=3, fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'parameter_parallel.png'), dpi=300)
    plt.close()

def plot_metrics_comparison(df):
    """Plot comparison of metrics for top trials"""
    # Get top 5 trials by score
    top_df = df.nlargest(5, 'score')
    
    # Metrics to plot
    metrics = ['paths_diff', 'crashes_diff', 'edges_diff', 'bitmap_diff', 'execs_diff']
    metric_labels = ['Paths', 'Crashes', 'Edges', 'Bitmap Coverage', 'Executions/sec']
    
    # Create figure
    fig, ax = plt.subplots(figsize=(14, 8))
    
    # Set width of bars
    barWidth = 0.15
    
    # Set positions of the bars on X axis
    r = np.arange(len(metrics))
    positions = [r]
    for i in range(1, len(top_df)):
        positions.append([x + barWidth for x in positions[i-1]])
    
    # Create bars
    for i, (_, row) in enumerate(top_df.iterrows()):
        values = [row[m] for m in metrics]
        ax.bar(positions[i], values, width=barWidth, 
               label=f'Trial {row["trial"]} (Score: {row["score"]:.2f})')
    
    # Add labels and title
    ax.set_xlabel('Metric', fontsize=14)
    ax.set_ylabel('Percentage Difference (%)', fontsize=14)
    ax.set_title('Performance Metrics for Top 5 Trials', fontsize=16)
    
    # Set x-axis ticks
    middle_positions = [positions[i][j] for j in range(len(metrics)) 
                       for i in range(len(top_df))]
    middle_positions = [sum(middle_positions[i:i+len(top_df)])/len(top_df) 
                       for i in range(0, len(middle_positions), len(top_df))]
    ax.set_xticks(middle_positions)
    ax.set_xticklabels(metric_labels)
    
    # Add a horizontal line at y=0
    ax.axhline(y=0, color='black', linestyle='-', alpha=0.3)
    
    # Add legend
    ax.legend(loc='upper center', bbox_to_anchor=(0.5, -0.15), ncol=3, fontsize=10)
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'metrics_comparison.png'), dpi=300)
    plt.close()

def plot_parameter_importance(df):
    """Plot parameter importance based on correlation with score"""
    # Parameters to analyze
    params = ['boost_duration', 'boost_weight', 'boost_decay', 'slice_us', 'slice_min_us']
    
    # Calculate correlation with score
    correlations = []
    for param in params:
        corr = df[param].corr(df['score'])
        correlations.append((param, abs(corr), corr > 0))
    
    # Sort by absolute correlation
    correlations.sort(key=lambda x: x[1], reverse=True)
    
    # Create figure
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Plot bars
    param_names = [c[0] for c in correlations]
    corr_values = [c[1] for c in correlations]
    colors = ['green' if c[2] else 'red' for c in correlations]
    
    bars = ax.bar(param_names, corr_values, color=colors)
    
    # Add correlation values on top of bars
    for i, v in enumerate(corr_values):
        ax.text(i, v + 0.02, f'{v:.2f}', ha='center', fontsize=10)
    
    # Add labels and title
    ax.set_xlabel('Parameter', fontsize=14)
    ax.set_ylabel('Absolute Correlation with Score', fontsize=14)
    ax.set_title('Parameter Importance (Correlation Analysis)', fontsize=16)
    
    # Add color legend
    from matplotlib.patches import Patch
    legend_elements = [
        Patch(facecolor='green', label='Positive Correlation'),
        Patch(facecolor='red', label='Negative Correlation')
    ]
    ax.legend(handles=legend_elements, loc='upper right')
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'parameter_importance.png'), dpi=300)
    plt.close()

def plot_parameter_distributions(df):
    """Plot distribution of parameters for top vs. bottom trials"""
    # Split trials into top and bottom half by score
    median_score = df['score'].median()
    top_df = df[df['score'] > median_score]
    bottom_df = df[df['score'] <= median_score]
    
    # Parameters to plot
    params = ['boost_duration', 'boost_weight', 'boost_decay', 'slice_us', 'slice_min_us']
    
    # Create figure with subplots
    fig, axes = plt.subplots(len(params), 1, figsize=(12, 15))
    
    for i, param in enumerate(params):
        ax = axes[i]
        
        # Plot histograms
        ax.hist(top_df[param], alpha=0.7, bins=10, label='Top Trials', color='green')
        ax.hist(bottom_df[param], alpha=0.7, bins=10, label='Bottom Trials', color='red')
        
        # Add vertical line for best trial
        best_trial = df.loc[df['score'].idxmax()]
        ax.axvline(x=best_trial[param], color='blue', linestyle='--', 
                  label=f'Best Trial ({best_trial["trial"]})')
        
        # Add labels
        ax.set_xlabel(param, fontsize=12)
        ax.set_ylabel('Count', fontsize=12)
        ax.set_title(f'Distribution of {param}', fontsize=14)
        
        # Add legend (only for the first subplot)
        if i == 0:
            ax.legend()
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'parameter_distributions.png'), dpi=300)
    plt.close()

def plot_best_trial_details(df):
    """Create a detailed visualization of the best trial"""
    # Get best trial
    best_trial = df.loc[df['score'].idxmax()]
    
    # Create figure with subplots
    fig = plt.figure(figsize=(14, 10))
    gs = gridspec.GridSpec(2, 2, width_ratios=[1, 1], height_ratios=[1, 1])
    
    # 1. Parameter values
    ax1 = plt.subplot(gs[0, 0])
    params = ['boost_duration', 'boost_weight', 'boost_decay', 'slice_us', 'slice_min_us']
    param_values = [best_trial[p] for p in params]
    
    ax1.barh(params, param_values, color='skyblue')
    ax1.set_title(f'Parameters for Best Trial (Trial {best_trial["trial"]})', fontsize=14)
    
    # Add parameter values as text
    for i, v in enumerate(param_values):
        ax1.text(v + (max(param_values) * 0.02), i, str(v), va='center')
    
    # 2. Metrics comparison
    ax2 = plt.subplot(gs[0, 1])
    metrics = ['paths_diff', 'crashes_diff', 'edges_diff', 'bitmap_diff', 'execs_diff']
    metric_labels = ['Paths', 'Crashes', 'Edges', 'Bitmap', 'Execs/sec']
    metric_values = [best_trial[m] for m in metrics]
    
    bars = ax2.bar(metric_labels, metric_values, color=['green' if v > 0 else 'red' for v in metric_values])
    ax2.set_title('Performance Metrics (% Difference)', fontsize=14)
    ax2.axhline(y=0, color='black', linestyle='-', alpha=0.3)
    
    # Add metric values as text
    for bar in bars:
        height = bar.get_height()
        if height < 0:
            va = 'top'
            offset = -10
        else:
            va = 'bottom'
            offset = 10
        ax2.text(bar.get_x() + bar.get_width()/2., height,
                f'{height:.2f}%', ha='center', va=va, 
                xytext=(0, offset), textcoords='offset points')
    
    # 3. Raw metrics comparison
    ax3 = plt.subplot(gs[1, 0])
    raw_metrics = ['paths', 'crashes', 'edges', 'bitmap', 'execs']
    custom_values = [best_trial[f'custom_{m}'] for m in raw_metrics]
    cfs_values = [best_trial[f'cfs_{m}'] for m in raw_metrics]
    
    x = np.arange(len(raw_metrics))
    width = 0.35
    
    ax3.bar(x - width/2, custom_values, width, label='Custom Scheduler')
    ax3.bar(x + width/2, cfs_values, width, label='CFS Scheduler')
    
    ax3.set_xticks(x)
    ax3.set_xticklabels(metric_labels)
    ax3.set_title('Raw Metrics Comparison', fontsize=14)
    ax3.legend()
    
    # 4. Score components
    ax4 = plt.subplot(gs[1, 1])
    
    # Calculate score components based on our scoring formula
    weights = {
        'paths_diff': 5.0,
        'crashes_diff': 10.0,
        'edges_diff': 2.0,
        'bitmap_diff': 3.0,
        'execs_diff': 1.0
    }
    
    components = {}
    for metric, weight in weights.items():
        components[metric] = best_trial[metric] * weight
    
    # Add bonus for finding crashes when CFS doesn't
    bonus = 0
    if best_trial['custom_crashes'] > 0 and best_trial['cfs_crashes'] == 0:
        bonus = 15.0
        components['crash_bonus'] = bonus
    
    ax4.bar(components.keys(), components.values(), color='purple')
    ax4.set_title('Score Components', fontsize=14)
    ax4.set_xticklabels(ax4.get_xticklabels(), rotation=45, ha='right')
    
    # Add component values as text
    for i, v in enumerate(components.values()):
        ax4.text(i, v + (max(components.values()) * 0.02), f'{v:.2f}', ha='center')
    
    # Add total score
    ax4.text(0.5, 0.9, f'Total Score: {best_trial["score"]:.2f}', 
             transform=ax4.transAxes, ha='center', fontsize=14,
             bbox=dict(facecolor='white', alpha=0.8, boxstyle='round,pad=0.5'))
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'best_trial_details.png'), dpi=300)
    plt.close()

def plot_score_vs_parameters(df):
    """Create scatter plots of score vs each parameter"""
    # Parameters to plot
    params = ['boost_duration', 'boost_weight', 'boost_decay', 'slice_us', 'slice_min_us']
    
    # Create figure with subplots
    fig, axes = plt.subplots(len(params), 1, figsize=(12, 15))
    
    for i, param in enumerate(params):
        ax = axes[i]
        
        # Create scatter plot
        scatter = ax.scatter(df[param], df['score'], c=df['score'], 
                            cmap='viridis', s=100, alpha=0.7)
        
        # Add best fit line
        z = np.polyfit(df[param], df['score'], 1)
        p = np.poly1d(z)
        ax.plot(df[param], p(df[param]), "r--", alpha=0.8)
        
        # Highlight best trial
        best_trial = df.loc[df['score'].idxmax()]
        ax.scatter(best_trial[param], best_trial['score'], s=200, c='red', 
                  marker='*', edgecolors='black', zorder=10, 
                  label=f'Best Trial ({best_trial["trial"]})')
        
        # Add labels
        ax.set_xlabel(param, fontsize=12)
        ax.set_ylabel('Score', fontsize=12)
        ax.set_title(f'Score vs {param}', fontsize=14)
        
        # Add correlation coefficient
        corr = df[param].corr(df['score'])
        ax.annotate(f'Correlation: {corr:.2f}', xy=(0.05, 0.95), 
                   xycoords='axes fraction', fontsize=12,
                   bbox=dict(boxstyle="round,pad=0.3", fc="white", ec="gray", alpha=0.8))
        
        # Add legend (only for the first subplot)
        if i == 0:
            ax.legend()
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'score_vs_parameters.png'), dpi=300)
    plt.close()

def main():
    """Main function to generate all visualizations"""
    print("Loading trial data...")
    trials = load_trial_data()
    
    if not trials:
        print("No trial data found!")
        return
    
    print(f"Found {len(trials)} trials")
    
    print("Converting to DataFrame...")
    df = create_dataframe(trials)
    
    print("Generating visualizations...")
    plot_optimization_history(df)
    plot_parameter_parallel(df)
    plot_metrics_comparison(df)
    plot_parameter_importance(df)
    plot_parameter_distributions(df)
    plot_best_trial_details(df)
    plot_score_vs_parameters(df)
    
    print(f"Visualizations saved to {output_dir}/")

if __name__ == "__main__":
    main()
