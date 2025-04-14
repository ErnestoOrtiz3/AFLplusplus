#!/usr/bin/env python3
"""
Generate simple visualizations from AFL++ scheduler optimization results
"""

import json
import glob
import os
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

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
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'optimization_history.png'), dpi=300)
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

def plot_best_trial_radar(df):
    """Create a radar chart for the best trial metrics"""
    # Get best trial
    best_trial = df.loc[df['score'].idxmax()]
    
    # Metrics to plot
    metrics = ['paths_diff', 'crashes_diff', 'edges_diff', 'bitmap_diff', 'execs_diff']
    metric_labels = ['Paths\nImprovement', 'Crashes\nImprovement', 'Edges\nImprovement', 
                    'Bitmap\nCoverage', 'Execution\nSpeed']
    
    # Normalize metrics for radar chart (0 to 1 scale)
    # We'll use min-max scaling across all trials
    normalized_metrics = {}
    for metric in metrics:
        min_val = df[metric].min()
        max_val = df[metric].max()
        if max_val > min_val:
            normalized_metrics[metric] = (best_trial[metric] - min_val) / (max_val - min_val)
        else:
            normalized_metrics[metric] = 0.5
    
    # Number of variables
    N = len(metrics)
    
    # Create angles for each metric
    angles = np.linspace(0, 2*np.pi, N, endpoint=False).tolist()
    angles += angles[:1]  # Close the loop
    
    # Create values for radar chart
    values = [normalized_metrics[m] for m in metrics]
    values += values[:1]  # Close the loop
    
    # Create figure
    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(polar=True))
    
    # Plot radar chart
    ax.plot(angles, values, 'o-', linewidth=2, markersize=8, label='Best Trial')
    ax.fill(angles, values, alpha=0.25)
    
    # Set labels
    ax.set_thetagrids(np.degrees(angles[:-1]), metric_labels)
    
    # Add raw metric values as text
    for i, metric in enumerate(metrics):
        value = best_trial[metric]
        angle = angles[i]
        x = 1.3 * np.cos(angle)
        y = 1.3 * np.sin(angle)
        ax.text(angle, 1.2, f'{value:.2f}%', 
               ha='center', va='center', fontsize=12,
               bbox=dict(facecolor='white', alpha=0.8, boxstyle='round,pad=0.2'))
    
    # Add title
    ax.set_title(f'Best Trial (Trial {best_trial["trial"]}) Performance Profile', fontsize=16)
    
    # Add parameter values
    params = ['boost_duration', 'boost_weight', 'boost_decay', 'slice_us', 'slice_min_us']
    param_text = '\n'.join([f'{p}: {best_trial[p]}' for p in params])
    plt.figtext(0.02, 0.02, f'Parameters:\n{param_text}', fontsize=12,
               bbox=dict(facecolor='white', alpha=0.8, boxstyle='round,pad=0.5'))
    
    # Add score
    plt.figtext(0.98, 0.02, f'Score: {best_trial["score"]:.2f}', fontsize=14,
               ha='right', bbox=dict(facecolor='white', alpha=0.8, boxstyle='round,pad=0.5'))
    
    plt.tight_layout()
    plt.savefig(os.path.join(output_dir, 'best_trial_radar.png'), dpi=300)
    plt.close()

def plot_parameter_heatmap(df):
    """Create heatmaps for parameter pairs vs score"""
    # Get parameters
    params = ['boost_duration', 'boost_weight', 'boost_decay', 'slice_us', 'slice_min_us']
    
    # Create all possible parameter pairs
    param_pairs = []
    for i in range(len(params)):
        for j in range(i+1, len(params)):
            param_pairs.append((params[i], params[j]))
    
    # Create a figure with subplots
    fig, axes = plt.subplots(2, 5, figsize=(20, 8))
    axes = axes.flatten()
    
    for i, (param1, param2) in enumerate(param_pairs):
        if i >= len(axes):
            break
            
        ax = axes[i]
        
        # Create scatter plot
        scatter = ax.scatter(df[param1], df[param2], c=df['score'], 
                           cmap='viridis', s=100, alpha=0.7)
        
        # Highlight best trial
        best_trial = df.loc[df['score'].idxmax()]
        ax.scatter(best_trial[param1], best_trial[param2], s=200, c='red', 
                 marker='*', edgecolors='black', zorder=10)
        
        # Add labels
        ax.set_xlabel(param1, fontsize=10)
        ax.set_ylabel(param2, fontsize=10)
        ax.set_title(f'{param1} vs {param2}', fontsize=12)
    
    # Add colorbar
    cbar_ax = fig.add_axes([0.92, 0.15, 0.02, 0.7])
    cbar = fig.colorbar(scatter, cax=cbar_ax)
    cbar.set_label('Score', fontsize=12)
    
    # Hide unused subplots
    for i in range(len(param_pairs), len(axes)):
        axes[i].axis('off')
    
    plt.tight_layout(rect=[0, 0, 0.9, 1])
    plt.savefig(os.path.join(output_dir, 'parameter_heatmap.png'), dpi=300)
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
    plot_metrics_comparison(df)
    plot_parameter_importance(df)
    plot_best_trial_radar(df)
    plot_parameter_heatmap(df)
    
    print(f"Visualizations saved to {output_dir}/")

if __name__ == "__main__":
    main()
