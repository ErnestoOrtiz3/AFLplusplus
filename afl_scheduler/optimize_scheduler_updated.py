#!/usr/bin/env python3
"""
Bayesian Optimization for AFL++ Scheduler Parameters

This script uses Optuna to find optimal parameter settings for the AFL++ CPU scheduler.
It runs benchmarks with different parameter combinations and learns from the results
to suggest increasingly better configurations.
"""

import optuna
import subprocess
import re
import os
import time
import json
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime
import glob
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("scheduler_optimization.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
DEFAULT_TRIALS = 20
DEFAULT_DURATION = 20  # minutes per benchmark
RESULTS_DIR = f"optuna_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
os.makedirs(RESULTS_DIR, exist_ok=True)

def parse_results(report_path):
    """Parse the comparison report to extract performance metrics."""
    try:
        with open(report_path, 'r') as f:
            content = f.read()
        
        # Extract key metrics
        metrics = {}
        
        # Extract executions/sec difference
        execs_match = re.search(r'Total executions/sec:.*?Diff=([-\d.]+)%', content)
        metrics['execs_diff'] = float(execs_match.group(1)) if execs_match else 0.0
        
        # Extract paths found difference
        paths_match = re.search(r'Total paths found:.*?Diff=([-\d.]+)%', content)
        metrics['paths_diff'] = float(paths_match.group(1)) if paths_match else 0.0
        
        # Extract crashes found difference
        crashes_match = re.search(r'Total crashes found:.*?Diff=([-\d.]+)%', content)
        metrics['crashes_diff'] = float(crashes_match.group(1)) if crashes_match else 0.0
        
        # Extract edges found difference
        edges_match = re.search(r'Total edges found:.*?Diff=([-\d.]+)%', content)
        metrics['edges_diff'] = float(edges_match.group(1)) if edges_match else 0.0
        
        # Extract bitmap coverage difference (in percentage points)
        bitmap_match = re.search(r'Average bitmap coverage:.*?Diff=([-\d.]+)pp', content)
        metrics['bitmap_diff'] = float(bitmap_match.group(1)) if bitmap_match else 0.0
        
        # Extract raw values too
        custom_execs_match = re.search(r'Total executions/sec: Custom=([\d.]+)', content)
        metrics['custom_execs'] = float(custom_execs_match.group(1)) if custom_execs_match else 0.0
        
        cfs_execs_match = re.search(r'Total executions/sec:.*?CFS=([\d.]+)', content)
        metrics['cfs_execs'] = float(cfs_execs_match.group(1)) if cfs_execs_match else 0.0
        
        custom_paths_match = re.search(r'Total paths found: Custom=(\d+)', content)
        metrics['custom_paths'] = int(custom_paths_match.group(1)) if custom_paths_match else 0
        
        cfs_paths_match = re.search(r'Total paths found:.*?CFS=(\d+)', content)
        metrics['cfs_paths'] = int(cfs_paths_match.group(1)) if cfs_paths_match else 0
        
        custom_crashes_match = re.search(r'Total crashes found: Custom=(\d+)', content)
        metrics['custom_crashes'] = int(custom_crashes_match.group(1)) if custom_crashes_match else 0
        
        cfs_crashes_match = re.search(r'Total crashes found:.*?CFS=(\d+)', content)
        metrics['cfs_crashes'] = int(cfs_crashes_match.group(1)) if cfs_crashes_match else 0
        
        custom_edges_match = re.search(r'Total edges found: Custom=(\d+)', content)
        metrics['custom_edges'] = int(custom_edges_match.group(1)) if custom_edges_match else 0
        
        cfs_edges_match = re.search(r'Total edges found:.*?CFS=(\d+)', content)
        metrics['cfs_edges'] = int(cfs_edges_match.group(1)) if cfs_edges_match else 0
        
        custom_bitmap_match = re.search(r'Average bitmap coverage: Custom=([\d.]+)%', content)
        metrics['custom_bitmap'] = float(custom_bitmap_match.group(1)) if custom_bitmap_match else 0.0
        
        cfs_bitmap_match = re.search(r'Average bitmap coverage:.*?CFS=([\d.]+)%', content)
        metrics['cfs_bitmap'] = float(cfs_bitmap_match.group(1)) if cfs_bitmap_match else 0.0
        
        return metrics
    except Exception as e:
        logger.error(f"Error parsing results: {e}")
        return {
            'execs_diff': 0.0, 'paths_diff': 0.0, 'crashes_diff': 0.0, 
            'edges_diff': 0.0, 'bitmap_diff': 0.0,
            'custom_execs': 0.0, 'cfs_execs': 0.0,
            'custom_paths': 0, 'cfs_paths': 0,
            'custom_crashes': 0, 'cfs_crashes': 0,
            'custom_edges': 0, 'cfs_edges': 0,
            'custom_bitmap': 0.0, 'cfs_bitmap': 0.0
        }

def find_latest_results_dir():
    """Find the most recently created enhanced_param_tests directory."""
    dirs = glob.glob("enhanced_param_tests_*")
    if not dirs:
        return None
    return max(dirs, key=os.path.getctime)

def calculate_score(metrics, weights=None):
    """Calculate a weighted score from the metrics."""
    if weights is None:
        weights = {
            'crashes_diff': 10.0,  # High weight for crashes
            'paths_diff': 5.0,     # Medium-high weight for paths
            'bitmap_diff': 3.0,    # Medium weight for coverage
            'edges_diff': 2.0,     # Medium-low weight for edges
            'execs_diff': 1.0      # Low weight for speed
        }
    
    # Calculate base score from percentage differences
    score = sum(metrics[metric] * weight for metric, weight in weights.items())
    
    # Add a modest bonus for finding any crashes when CFS finds none
    # This is a tiebreaker rather than a dominant factor
    if metrics['custom_crashes'] > 0 and metrics['cfs_crashes'] == 0:
        score += 15.0
    
    return score

def objective(trial):
    """Objective function for Optuna optimization."""
    # Define parameter search spaces
    boost_duration = trial.suggest_int('boost_duration', 500000, 5000000, step=500000)
    boost_weight = trial.suggest_int('boost_weight', 100, 5000, step=100)
    boost_decay = trial.suggest_int('boost_decay', 500000, 5000000, step=500000)
    slice_us = trial.suggest_int('slice_us', 5000, 50000, step=5000)
    slice_min_us = trial.suggest_int('slice_min_us', 1000, 10000, step=1000)
    
    # Ensure slice_min_us <= slice_us
    slice_min_us = min(slice_min_us, slice_us)
    
    # Log the parameters being tested
    logger.info(f"Trial {trial.number}: Testing parameters: boost_duration={boost_duration}, "
                f"boost_weight={boost_weight}, boost_decay={boost_decay}, "
                f"slice_us={slice_us}, slice_min_us={slice_min_us}")
    
    # Run benchmark with these parameters
    test_name = f"trial_{trial.number}"
    cmd = [
        "sudo", "/home/ernesto/Documents/AFLplusplus/afl_scheduler/param_test_enhanced_fixed.sh", 
        "custom", test_name, 
        str(boost_duration), str(boost_weight), str(boost_decay),
        str(slice_us), str(slice_min_us)
    ]
    
    try:
        subprocess.run(cmd, check=True)
        
        # Find the latest results directory
        results_dir = find_latest_results_dir()
        if not results_dir:
            logger.error("Could not find results directory")
            return float('-inf')
        
        # Find the comparison report
        report_path = os.path.join(results_dir, test_name, "comparison_report.txt")
        if not os.path.exists(report_path):
            logger.error(f"Comparison report not found at {report_path}")
            return float('-inf')
        
        # Parse results
        metrics = parse_results(report_path)
        
        # Calculate score
        score = calculate_score(metrics)
        
        # Save trial results
        trial_results = {
            'trial': trial.number,
            'params': {
                'boost_duration': boost_duration,
                'boost_weight': boost_weight,
                'boost_decay': boost_decay,
                'slice_us': slice_us,
                'slice_min_us': slice_min_us
            },
            'metrics': metrics,
            'score': score
        }
        
        with open(os.path.join(RESULTS_DIR, f"trial_{trial.number}.json"), 'w') as f:
            json.dump(trial_results, f, indent=2)
        
        logger.info(f"Trial {trial.number} completed with score: {score}")
        logger.info(f"Metrics: paths_diff={metrics['paths_diff']}%, "
                   f"crashes_diff={metrics['crashes_diff']}%, "
                   f"edges_diff={metrics['edges_diff']}%, "
                   f"bitmap_diff={metrics['bitmap_diff']}pp, "
                   f"execs_diff={metrics['execs_diff']}%")
        
        return score
    
    except Exception as e:
        logger.error(f"Error in trial {trial.number}: {e}")
        return float('-inf')

def visualize_results(study):
    """Create visualizations of the optimization results."""
    os.makedirs(os.path.join(RESULTS_DIR, "plots"), exist_ok=True)
    
    try:
        # Try to import plotly for visualizations
        import plotly
        
        # Create interactive HTML visualizations (these don't require kaleido)
        fig = optuna.visualization.plot_optimization_history(study)
        fig.write_html(os.path.join(RESULTS_DIR, "plots", "optimization_history.html"))
        
        fig = optuna.visualization.plot_param_importances(study)
        fig.write_html(os.path.join(RESULTS_DIR, "plots", "param_importances.html"))
        
        fig = optuna.visualization.plot_parallel_coordinate(study)
        fig.write_html(os.path.join(RESULTS_DIR, "plots", "parallel_coordinate.html"))
        
        fig = optuna.visualization.plot_contour(study, params=["slice_us", "slice_min_us"])
        fig.write_html(os.path.join(RESULTS_DIR, "plots", "slice_contour.html"))
        
        fig = optuna.visualization.plot_contour(study, params=["boost_duration", "boost_weight"])
        fig.write_html(os.path.join(RESULTS_DIR, "plots", "boost_contour.html"))
        
        # Try to save static images if kaleido is available
        try:
            fig = optuna.visualization.plot_optimization_history(study)
            fig.write_image(os.path.join(RESULTS_DIR, "plots", "optimization_history.png"))
            
            fig = optuna.visualization.plot_param_importances(study)
            fig.write_image(os.path.join(RESULTS_DIR, "plots", "param_importances.png"))
            
            fig = optuna.visualization.plot_parallel_coordinate(study)
            fig.write_image(os.path.join(RESULTS_DIR, "plots", "parallel_coordinate.png"))
            
            fig = optuna.visualization.plot_contour(study, params=["slice_us", "slice_min_us"])
            fig.write_image(os.path.join(RESULTS_DIR, "plots", "slice_contour.png"))
            
            fig = optuna.visualization.plot_contour(study, params=["boost_duration", "boost_weight"])
            fig.write_image(os.path.join(RESULTS_DIR, "plots", "boost_contour.png"))
            
            logger.info("Static plot images saved successfully")
        except Exception as e:
            logger.warning(f"Could not save static plot images (kaleido may be missing): {e}")
            logger.info("Interactive HTML plots are still available")
    
    except ImportError:
        logger.warning("Plotly not installed. Skipping visualizations.")
        
        # Create basic matplotlib visualizations as fallback
        try:
            # Create a simple optimization history plot
            plt.figure(figsize=(10, 6))
            trials = study.trials
            values = [t.value for t in trials if t.value is not None]
            plt.plot(values)
            plt.xlabel('Trial')
            plt.ylabel('Score')
            plt.title('Optimization History')
            plt.savefig(os.path.join(RESULTS_DIR, "plots", "optimization_history_simple.png"))
            plt.close()
            
            logger.info("Simple matplotlib plots saved as fallback")
        except Exception as e:
            logger.warning(f"Could not create fallback matplotlib plots: {e}")

def create_summary_report(study):
    """Create a summary report of the optimization results."""
    # Collect all trial results
    all_trials = []
    for trial_file in glob.glob(os.path.join(RESULTS_DIR, "trial_*.json")):
        with open(trial_file, 'r') as f:
            trial_data = json.load(f)
            all_trials.append(trial_data)
    
    # Sort by score
    all_trials.sort(key=lambda x: x['score'], reverse=True)
    
    # Create summary report
    report = ["# AFL++ Scheduler Parameter Optimization Report\n"]
    report.append(f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    report.append(f"Number of trials: {len(all_trials)}\n")
    report.append("\n## Best Parameters\n")
    
    best_trial = all_trials[0]
    report.append(f"Score: {best_trial['score']:.2f}\n")
    report.append("Parameters:")
    for param, value in best_trial['params'].items():
        report.append(f"- {param}: {value}")
    
    report.append("\nMetrics:")
    report.append(f"- Paths difference: {best_trial['metrics']['paths_diff']:.2f}%")
    report.append(f"- Crashes difference: {best_trial['metrics']['crashes_diff']:.2f}%")
    report.append(f"- Edges difference: {best_trial['metrics']['edges_diff']:.2f}%")
    report.append(f"- Bitmap coverage difference: {best_trial['metrics']['bitmap_diff']:.2f}pp")
    report.append(f"- Executions/sec difference: {best_trial['metrics']['execs_diff']:.2f}%")
    
    report.append("\n## Top 5 Configurations\n")
    for i, trial in enumerate(all_trials[:5]):
        report.append(f"### Rank {i+1} (Score: {trial['score']:.2f})\n")
        report.append("Parameters:")
        for param, value in trial['params'].items():
            report.append(f"- {param}: {value}")
        report.append("\nMetrics:")
        report.append(f"- Paths difference: {trial['metrics']['paths_diff']:.2f}%")
        report.append(f"- Crashes difference: {trial['metrics']['crashes_diff']:.2f}%")
        report.append(f"- Edges difference: {trial['metrics']['edges_diff']:.2f}%")
        report.append(f"- Bitmap coverage difference: {trial['metrics']['bitmap_diff']:.2f}pp")
        report.append(f"- Executions/sec difference: {trial['metrics']['execs_diff']:.2f}%")
        report.append("\n")
    
    report.append("## Parameter Importance\n")
    importance = optuna.importance.get_param_importances(study)
    for param, score in importance.items():
        report.append(f"- {param}: {score:.4f}")
    
    report.append("\n## All Trials\n")
    report.append("| Trial | Score | boost_duration | boost_weight | boost_decay | slice_us | slice_min_us | paths_diff | crashes_diff | edges_diff | bitmap_diff | execs_diff |")
    report.append("|-------|-------|---------------|--------------|-------------|----------|--------------|------------|--------------|------------|-------------|------------|")
    
    for trial in all_trials:
        p = trial['params']
        m = trial['metrics']
        report.append(f"| {trial['trial']} | {trial['score']:.2f} | {p['boost_duration']} | {p['boost_weight']} | {p['boost_decay']} | {p['slice_us']} | {p['slice_min_us']} | {m['paths_diff']:.2f}% | {m['crashes_diff']:.2f}% | {m['edges_diff']:.2f}% | {m['bitmap_diff']:.2f}pp | {m['execs_diff']:.2f}% |")
    
    # Write report to file
    with open(os.path.join(RESULTS_DIR, "optimization_report.md"), 'w') as f:
        f.write("\n".join(report))
    
    # Also create a CSV for easy analysis
    df = pd.DataFrame([
        {
            'trial': t['trial'],
            'score': t['score'],
            'boost_duration': t['params']['boost_duration'],
            'boost_weight': t['params']['boost_weight'],
            'boost_decay': t['params']['boost_decay'],
            'slice_us': t['params']['slice_us'],
            'slice_min_us': t['params']['slice_min_us'],
            'paths_diff': t['metrics']['paths_diff'],
            'crashes_diff': t['metrics']['crashes_diff'],
            'edges_diff': t['metrics']['edges_diff'],
            'bitmap_diff': t['metrics']['bitmap_diff'],
            'execs_diff': t['metrics']['execs_diff'],
            'custom_paths': t['metrics']['custom_paths'],
            'cfs_paths': t['metrics']['cfs_paths'],
            'custom_crashes': t['metrics']['custom_crashes'],
            'cfs_crashes': t['metrics']['cfs_crashes']
        }
        for t in all_trials
    ])
    
    df.to_csv(os.path.join(RESULTS_DIR, "all_trials.csv"), index=False)

def main(n_trials=DEFAULT_TRIALS, duration=DEFAULT_DURATION):
    """Main function to run the optimization."""
    logger.info(f"Starting optimization with {n_trials} trials, {duration} minutes per benchmark")
    logger.info(f"Results will be saved to {RESULTS_DIR}")
    
    # Create a study object and optimize
    study = optuna.create_study(
        direction='maximize',
        study_name="afl_scheduler_optimization",
        storage=f"sqlite:///{RESULTS_DIR}/optuna.db"
    )
    
    try:
        study.optimize(objective, n_trials=n_trials)
        
        # Print results
        logger.info("Optimization completed!")
        logger.info(f"Best parameters: {study.best_params}")
        logger.info(f"Best value: {study.best_value}")
        
        # Create visualizations
        visualize_results(study)
        logger.info(f"Visualizations saved to {RESULTS_DIR}/plots/")
        
        # Create summary report
        create_summary_report(study)
        logger.info(f"Summary report saved to {RESULTS_DIR}/optimization_report.md")
        
        return study
    
    except KeyboardInterrupt:
        logger.info("Optimization interrupted by user.")
        
        # Still create report with partial results
        create_summary_report(study)
        logger.info(f"Partial summary report saved to {RESULTS_DIR}/optimization_report.md")
        
        return study

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="Optimize AFL++ scheduler parameters")
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS,
                        help=f"Number of trials to run (default: {DEFAULT_TRIALS})")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION,
                        help=f"Duration of each benchmark in minutes (default: {DEFAULT_DURATION})")
    
    args = parser.parse_args()
    
    main(n_trials=args.trials, duration=args.duration)
