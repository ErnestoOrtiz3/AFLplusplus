#!/usr/bin/env python3
"""
Gaussian Process-Based Bayesian Optimization for AFL++ Scheduler Parameters

This script uses scikit-learn's Gaussian Process Regression to find optimal
parameter settings for the AFL++ CPU scheduler by efficiently exploring the
parameter space and learning from benchmark results.
"""

import os
import sys
import time
import json
import glob
import logging
import subprocess
import numpy as np
from numpy import float32, float64
import pandas as pd
from datetime import datetime
from pathlib import Path
from sklearn.gaussian_process import GaussianProcessRegressor
from sklearn.gaussian_process.kernels import Matern, WhiteKernel
import matplotlib.pyplot as plt
from matplotlib import gridspec
from scipy.stats import norm

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("gp_scheduler_optimization.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("gp_optimizer")

# Constants
DEFAULT_TRIALS = 2
DEFAULT_DURATION = 2  # minutes per benchmark
DEFAULT_INITIAL_SAMPLES = 1
DEFAULT_REPLICATIONS = 2  # Number of replications for each parameter combination

# Create results directory
TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
RESULTS_DIR = f"gp_optimization_results_{TIMESTAMP}"
os.makedirs(RESULTS_DIR, exist_ok=True)

# Parameter space definition
PARAM_SPACE = {
    'boost_duration': {
        'min': 100000,    # 0.1 seconds
        'max': 5000000,   # 5 seconds
        'step': 100000,   # 0.1 second steps
        'type': int
    },
    'boost_weight': {
        'min': 100,
        'max': 5000,
        'step': 100,
        'type': int
    },
    'boost_decay': {
        'min': 500000,    # 0.5 seconds
        'max': 5000000,   # 5 seconds
        'step': 500000,   # 0.5 second steps
        'type': int
    },
    'slice_us': {
        'min': 5000,      # 5 milliseconds
        'max': 50000,     # 50 milliseconds
        'step': 5000,     # 5 millisecond steps
        'type': int
    },
    'slice_min_us': {
        'min': 1000,      # 1 millisecond
        'max': 10000,     # 10 milliseconds
        'step': 1000,     # 1 millisecond steps
        'type': int
    }
}

# Metric weights for composite score
METRIC_WEIGHTS = {
    'custom_crashes': 20.0,   # High weight for crashes
    'custom_paths': 0.04,     # Medium-high weight for paths
    'custom_bitmap': 1.0,    # Medium weight for coverage
    'custom_edges': 0.01,     # Medium-low weight for edges
    'custom_execs': 0.001      # Low weight for speed
}

def generate_random_parameters():
    """Generate a random valid parameter combination."""
    params = {}
    for param_name, param_config in PARAM_SPACE.items():
        # Generate a random value within the range
        min_val = param_config['min']
        max_val = param_config['max']
        step = param_config['step']

        # Calculate the number of possible steps
        num_steps = (max_val - min_val) // step + 1

        # Generate a random step index and calculate the value
        step_idx = np.random.randint(0, num_steps)
        value = min_val + step_idx * step

        # Convert to the appropriate type
        params[param_name] = param_config['type'](value)

    # Ensure slice_min_us <= slice_us
    params['slice_min_us'] = min(params['slice_min_us'], params['slice_us'])

    return params

def run_benchmark(params, trial_num, duration, replications=DEFAULT_REPLICATIONS):
    """Run a benchmark with the given parameters and return the results.

    Args:
        params: Dictionary of parameter values
        trial_num: Trial number
        duration: Duration of each benchmark in minutes
        replications: Number of replications to run for this parameter combination

    Returns:
        Dictionary with parameters, metrics, and score, or None if all replications failed
    """
    logger.info(f"Trial {trial_num}: Running benchmark with parameters: {params} ({replications} replications)")

    all_metrics = []
    all_scores = []

    for rep in range(1, replications + 1):
        # Create a unique test name for this trial and replication
        test_name = f"gp_trial_{trial_num}_rep_{rep}"

        logger.info(f"Starting replication {rep}/{replications}")

        # Construct the command to run the benchmark
        cmd = [
            "sudo",
            "./afl_scheduler/param_test_enhanced_fixed.sh",
            "custom",
            test_name,
            str(params['boost_duration']),
            str(params['boost_weight']),
            str(params['boost_decay']),
            str(params['slice_us']),
            str(params['slice_min_us'])
        ]

        # Log the command
        logger.info(f"Running command: {' '.join(cmd)}")

        # Run the benchmark
        try:
            subprocess.run(cmd, check=True)
            logger.info(f"Benchmark replication {rep} completed successfully")
        except subprocess.CalledProcessError as e:
            logger.error(f"Benchmark replication {rep} failed with error: {e}")
            continue  # Try the next replication

        # Find the results directory
        results_dir = None
        for d in sorted(Path(".").glob("enhanced_param_tests_*"), reverse=True):
            if d.is_dir() and (d / test_name).exists():
                results_dir = d / test_name
                break

        if not results_dir:
            logger.error(f"Could not find results directory for trial {trial_num}, replication {rep}")
            continue  # Try the next replication

        # Parse the results
        report_path = results_dir / "comparison_report.txt"
        if not report_path.exists():
            logger.error(f"Comparison report not found for trial {trial_num}, replication {rep}")
            continue  # Try the next replication

        # Parse the comparison report to extract metrics
        metrics = parse_comparison_report(report_path)

        # Calculate the composite score
        score = calculate_score(metrics)

        logger.info(f"Replication {rep} score: {score}")

        # Store the metrics and score for this replication
        all_metrics.append(metrics)
        all_scores.append(score)

    # If all replications failed, return None
    if not all_scores:
        logger.error(f"All replications failed for trial {trial_num}")
        return None

    # Average the metrics and scores
    avg_metrics = {}
    for key in all_metrics[0].keys():
        avg_metrics[key] = sum(m[key] for m in all_metrics) / len(all_metrics)

    avg_score = sum(all_scores) / len(all_scores)

    logger.info(f"Trial {trial_num}: Average score across {len(all_scores)} replications: {avg_score}")

    # Save the results
    save_trial_results(trial_num, params, avg_metrics, avg_score, all_metrics, all_scores)

    return {
        'params': params,
        'metrics': avg_metrics,
        'score': avg_score,
        'all_metrics': all_metrics,
        'all_scores': all_scores
    }

def parse_comparison_report(report_path):
    """Parse the comparison report to extract metrics."""
    try:
        with open(report_path, 'r') as f:
            content = f.read()

        # Initialize metrics dictionary
        metrics = {}

        # Extract key metrics using regular expressions
        import re

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

        cfs_execs_match = re.search(r'Total executions/sec:.*?EEVDF=([\d.]+)', content)
        metrics['cfs_execs'] = float(cfs_execs_match.group(1)) if cfs_execs_match else 0.0

        custom_paths_match = re.search(r'Total paths found: Custom=(\d+)', content)
        metrics['custom_paths'] = int(custom_paths_match.group(1)) if custom_paths_match else 0

        cfs_paths_match = re.search(r'Total paths found:.*?EEVDF=(\d+)', content)
        metrics['cfs_paths'] = int(cfs_paths_match.group(1)) if cfs_paths_match else 0

        custom_crashes_match = re.search(r'Total crashes found: Custom=(\d+)', content)
        metrics['custom_crashes'] = int(custom_crashes_match.group(1)) if custom_crashes_match else 0

        cfs_crashes_match = re.search(r'Total crashes found:.*?EEVDF=(\d+)', content)
        metrics['cfs_crashes'] = int(cfs_crashes_match.group(1)) if cfs_crashes_match else 0

        custom_edges_match = re.search(r'Total edges found: Custom=(\d+)', content)
        metrics['custom_edges'] = int(custom_edges_match.group(1)) if custom_edges_match else 0

        cfs_edges_match = re.search(r'Total edges found:.*?EEVDF=(\d+)', content)
        metrics['cfs_edges'] = int(cfs_edges_match.group(1)) if cfs_edges_match else 0

        custom_bitmap_match = re.search(r'Average bitmap coverage: Custom=([\d.]+)%', content)
        metrics['custom_bitmap'] = float(custom_bitmap_match.group(1)) if custom_bitmap_match else 0.0

        cfs_bitmap_match = re.search(r'Average bitmap coverage:.*?EEVDF=([\d.]+)%', content)
        metrics['cfs_bitmap'] = float(cfs_bitmap_match.group(1)) if cfs_bitmap_match else 0.0

        return metrics
    except Exception as e:
        logger.error(f"Error parsing comparison report: {e}")
        return {
            'execs_diff': 0.0, 'paths_diff': 0.0, 'crashes_diff': 0.0,
            'edges_diff': 0.0, 'bitmap_diff': 0.0,
            'custom_execs': 0.0, 'cfs_execs': 0.0,
            'custom_paths': 0, 'cfs_paths': 0,
            'custom_crashes': 0, 'cfs_crashes': 0,
            'custom_edges': 0, 'cfs_edges': 0,
            'custom_bitmap': 0.0, 'cfs_bitmap': 0.0
        }

def calculate_score(metrics, weights=None):
    """Calculate a composite score from the metrics."""
    if weights is None:
        weights = METRIC_WEIGHTS

    # Calculate score from raw custom metrics
    score = sum(metrics[metric] * weight for metric, weight in weights.items() if metric in metrics)

    return score

def save_trial_results(trial_num, params, metrics, score, all_metrics=None, all_scores=None):
    """Save the results of a trial to disk.

    Args:
        trial_num: Trial number
        params: Parameter values
        metrics: Average metrics across replications
        score: Average score across replications
        all_metrics: List of metrics for each replication (optional)
        all_scores: List of scores for each replication (optional)
    """
    # Convert any NumPy types to native Python types for JSON serialization
    serializable_params = {k: float(v) if isinstance(v, (np.float32, np.float64)) else v
                          for k, v in params.items()}

    serializable_metrics = {k: float(v) if isinstance(v, (np.float32, np.float64)) else v
                           for k, v in metrics.items()}

    # Create a dictionary with all the information
    result = {
        'trial': trial_num,
        'params': serializable_params,
        'metrics': serializable_metrics,
        'score': float(score),  # Ensure score is a native Python float
        'timestamp': datetime.now().isoformat()
    }

    # Add replication data if available
    if all_metrics and all_scores:
        # Convert any NumPy types in the replication data
        serializable_all_metrics = []
        for m in all_metrics:
            serializable_all_metrics.append({
                k: float(v) if isinstance(v, (np.float32, np.float64)) else v
                for k, v in m.items()
            })

        serializable_all_scores = [float(s) for s in all_scores]

        result['replications'] = {
            'count': len(all_scores),
            'all_metrics': serializable_all_metrics,
            'all_scores': serializable_all_scores,
            'score_std': float(np.std(all_scores)) if len(all_scores) > 1 else 0.0
        }

    # Save as JSON
    with open(os.path.join(RESULTS_DIR, f"trial_{trial_num}.json"), 'w') as f:
        json.dump(result, f, indent=2)

    # Update the CSV file with all trials
    update_trials_csv(trial_num, params, metrics, score, all_scores)

def update_trials_csv(trial_num, params, metrics, score, all_scores=None):
    """Update the CSV file with all trials.

    Args:
        trial_num: Trial number
        params: Parameter values
        metrics: Average metrics across replications
        score: Average score across replications
        all_scores: List of scores for each replication (optional)
    """
    # Create a row for this trial
    row = {
        'trial': trial_num,
        'score': score,
        'timestamp': datetime.now().isoformat()
    }

    # Add replication statistics if available
    if all_scores and len(all_scores) > 1:
        row['score_std'] = np.std(all_scores)
        row['score_min'] = min(all_scores)
        row['score_max'] = max(all_scores)
        row['replications'] = len(all_scores)
    else:
        row['score_std'] = 0.0
        row['score_min'] = score
        row['score_max'] = score
        row['replications'] = 1 if all_scores else 1

    # Add parameters
    for param, value in params.items():
        row[param] = value

    # Add metrics
    for metric, value in metrics.items():
        row[metric] = value

    # Create or update the CSV file
    csv_path = os.path.join(RESULTS_DIR, "all_trials.csv")

    if os.path.exists(csv_path):
        # Read existing CSV and append the new row
        df = pd.read_csv(csv_path)
        new_df = pd.DataFrame([row])
        df = pd.concat([df, new_df], ignore_index=True)
    else:
        # Create a new CSV with this row
        df = pd.DataFrame([row])

    # Save the CSV
    df.to_csv(csv_path, index=False)

def parameters_to_vector(params):
    """Convert a parameter dictionary to a vector for GP input."""
    return np.array([params[param] for param in sorted(PARAM_SPACE.keys())])

def vector_to_parameters(vector):
    """Convert a vector back to a parameter dictionary."""
    params = {}
    for i, param in enumerate(sorted(PARAM_SPACE.keys())):
        params[param] = PARAM_SPACE[param]['type'](vector[i])

    # Ensure slice_min_us <= slice_us
    params['slice_min_us'] = min(params['slice_min_us'], params['slice_us'])

    return params

def normalize_parameters(params):
    """Normalize parameters to [0, 1] range for GP."""
    normalized = {}
    for param, value in params.items():
        min_val = PARAM_SPACE[param]['min']
        max_val = PARAM_SPACE[param]['max']
        normalized[param] = (value - min_val) / (max_val - min_val)
    return normalized

def denormalize_parameters(normalized_params):
    """Convert normalized parameters back to their original range."""
    params = {}
    for param, value in normalized_params.items():
        min_val = PARAM_SPACE[param]['min']
        max_val = PARAM_SPACE[param]['max']
        step = PARAM_SPACE[param]['step']

        # Convert to original range
        denorm_value = min_val + value * (max_val - min_val)

        # Round to nearest step
        steps = round((denorm_value - min_val) / step)
        params[param] = PARAM_SPACE[param]['type'](min_val + steps * step)

    # Ensure slice_min_us <= slice_us
    params['slice_min_us'] = min(params['slice_min_us'], params['slice_us'])

    return params

def expected_improvement(X, model, y_best, xi=0.01):
    """
    Compute the Expected Improvement acquisition function.

    Args:
        X: Points at which to evaluate the acquisition function
        model: Trained GP model
        y_best: Best observed value
        xi: Exploration-exploitation trade-off parameter

    Returns:
        Expected improvement at points X
    """
    mu, sigma = model.predict(X, return_std=True)

    # Handle case where sigma is very small or zero
    with np.errstate(divide='ignore'):
        # Improvement over best observed value
        imp = mu - y_best - xi

        # Calculate Z score
        Z = imp / sigma

        # Calculate expected improvement
        ei = imp * norm.cdf(Z) + sigma * norm.pdf(Z)

        # Set expected improvement to 0 where sigma is very small
        ei[sigma < 1e-10] = 0.0

    return ei

def train_gp_model(X_sample, y_sample):
    """
    Train a Gaussian Process model on the provided data.

    Args:
        X_sample: Parameter vectors (normalized)
        y_sample: Observed scores

    Returns:
        Tuple of (trained GP model, score shift value, shifted y values)
    """
    # Shift scores to ensure they're positive (helps with GP stability)
    # Add a constant to all scores to make them positive
    min_score = min(y_sample)
    if min_score < 0:
        score_shift = abs(min_score) + 500.0  # Add 500 to ensure all values are comfortably positive
    else:
        score_shift = 500.0  # Still add a constant for stability

    shifted_y_sample = y_sample + score_shift

    logger.info(f"Shifting scores by {score_shift} to ensure positive values for GP stability")

    # Train the GP model with explicit noise handling
    # Matern kernel with nu=2.5 (once-differentiable functions)
    # Plus WhiteKernel to model observation noise
    kernel = Matern(nu=2.5, length_scale_bounds=(1e-2, 1e2)) + WhiteKernel(noise_level=1e-2, noise_level_bounds=(1e-5, 1e1))

    model = GaussianProcessRegressor(
        kernel=kernel,
        alpha=1e-2,  # Explicit noise regularization
        n_restarts_optimizer=10,
        normalize_y=True,  # Normalize target values
        random_state=42
    )

    # Fit the model on the shifted scores
    model.fit(X_sample, shifted_y_sample)

    # Log the learned kernel parameters
    logger.info(f"Trained GP model with kernel: {model.kernel_}")
    logger.info(f"Kernel hyperparameters: {model.kernel_.get_params()}")

    return model, score_shift, shifted_y_sample


def propose_next_parameters(X_sample, y_sample, bounds):
    """
    Propose the next parameters to evaluate using GP and Expected Improvement.

    Args:
        X_sample: Previously sampled parameters (normalized)
        y_sample: Observed scores
        bounds: Parameter bounds (normalized)

    Returns:
        Next parameters to evaluate (normalized)
    """
    from scipy.optimize import minimize

    # Train the GP model
    model, _, shifted_y_sample = train_gp_model(X_sample, y_sample)

    # Find the best observed value (using shifted scores)
    y_best = shifted_y_sample.max()

    # Define the negative expected improvement function (for minimization)
    def negative_ei(x):
        return -expected_improvement(x.reshape(1, -1), model, y_best)

    # Optimize the acquisition function
    best_ei = -np.inf
    best_x = None

    # Try multiple random starting points for more reliable optimization
    n_restarts = 15  # Increased from 10
    for _ in range(n_restarts):
        # Random starting point
        x0 = np.random.rand(len(bounds))

        # Optimize from this starting point
        result = minimize(
            negative_ei,
            x0,
            bounds=bounds,
            method='L-BFGS-B'
        )

        if result.fun < -best_ei:
            best_ei = -result.fun
            best_x = result.x

    logger.info(f"Best expected improvement: {best_ei}")

    return best_x


def predict_optimal_parameters(X_sample, y_sample, bounds):
    """
    Predict the optimal parameters using the trained GP model.

    This function trains a GP model on all collected data and then
    finds the parameter combination that maximizes the predicted score.

    Args:
        X_sample: All sampled parameters (normalized)
        y_sample: All observed scores
        bounds: Parameter bounds (normalized)

    Returns:
        Tuple of (optimal parameters dict, predicted score)
    """
    from scipy.optimize import minimize

    logger.info("Predicting optimal parameters using the trained GP model...")

    # Train the GP model on all data
    model, score_shift, _ = train_gp_model(X_sample, y_sample)

    # Define the negative predicted score function (for minimization)
    def negative_prediction(x):
        x_reshaped = x.reshape(1, -1)
        pred, _ = model.predict(x_reshaped, return_std=True)
        return -pred[0]  # Negative because we're minimizing

    # Optimize to find the parameters that maximize the predicted score
    best_pred = np.inf
    best_x = None

    # Try multiple random starting points for more reliable optimization
    n_restarts = 30  # More restarts for final prediction
    for _ in range(n_restarts):
        # Random starting point
        x0 = np.random.rand(len(bounds))

        # Optimize from this starting point
        result = minimize(
            negative_prediction,
            x0,
            bounds=bounds,
            method='L-BFGS-B'
        )

        if result.fun < best_pred:
            best_pred = result.fun
            best_x = result.x

    # Convert normalized parameters to actual values
    optimal_params = {}
    for i, param in enumerate(sorted(PARAM_SPACE.keys())):
        optimal_params[param] = best_x[i]

    optimal_params = denormalize_parameters(optimal_params)

    # Calculate the predicted score (removing the shift)
    predicted_score = -best_pred - score_shift

    logger.info(f"Predicted optimal parameters: {optimal_params}")
    logger.info(f"Predicted score: {predicted_score}")

    return optimal_params, predicted_score

def main(n_trials=DEFAULT_TRIALS, duration=DEFAULT_DURATION, initial_samples=DEFAULT_INITIAL_SAMPLES, replications=DEFAULT_REPLICATIONS):
    """Main function to run the optimization.

    Args:
        n_trials: Total number of trials to run
        duration: Duration of each benchmark in minutes
        initial_samples: Number of initial random samples
        replications: Number of replications for each parameter combination
    """
    logger.info(f"Starting Gaussian Process optimization with {n_trials} trials, {duration} minutes per benchmark")
    logger.info(f"Using {replications} replications for each parameter combination")
    logger.info(f"Results will be saved to {RESULTS_DIR}")

    # Save configuration
    # Create a serializable version of PARAM_SPACE (convert type objects to strings)
    serializable_param_space = {}
    for param, config in PARAM_SPACE.items():
        serializable_param_space[param] = {
            'min': config['min'],
            'max': config['max'],
            'step': config['step'],
            'type': config['type'].__name__  # Convert type to string
        }

    config = {
        'n_trials': n_trials,
        'duration': duration,
        'initial_samples': initial_samples,
        'replications': replications,
        'param_space': serializable_param_space,
        'metric_weights': METRIC_WEIGHTS,
        'start_time': datetime.now().isoformat()
    }

    with open(os.path.join(RESULTS_DIR, "config.json"), 'w') as f:
        json.dump(config, f, indent=2)

    # Step 1: Initial random sampling
    logger.info(f"Starting initial random sampling ({initial_samples} samples)")

    X_sample = []  # Normalized parameter vectors
    y_sample = []  # Observed scores

    for i in range(1, initial_samples + 1):
        # Generate random parameters
        params = generate_random_parameters()

        # Run benchmark
        result = run_benchmark(params, i, duration)

        if result:
            # Store normalized parameters and score
            X_sample.append(list(normalize_parameters(params).values()))
            y_sample.append(result['score'])

            logger.info(f"Initial sample {i} completed with score: {result['score']}")
        else:
            logger.error(f"Initial sample {i} failed")

    # Convert to numpy arrays
    X_sample = np.array(X_sample)
    y_sample = np.array(y_sample)

    # Step 2: Bayesian optimization loop
    logger.info("Starting Bayesian optimization loop")

    # Define normalized bounds for optimization
    bounds = [(0, 1) for _ in range(len(PARAM_SPACE))]

    for i in range(initial_samples + 1, n_trials + 1):
        # Propose next parameters using GP and EI
        next_params_normalized = propose_next_parameters(X_sample, y_sample, bounds)

        # Convert normalized parameters to actual values
        param_dict = {}
        for j, param in enumerate(sorted(PARAM_SPACE.keys())):
            param_dict[param] = next_params_normalized[j]

        next_params = denormalize_parameters(param_dict)

        # Run benchmark with these parameters
        result = run_benchmark(next_params, i, duration)

        if result:
            # Add to our sample data
            X_sample = np.vstack((X_sample, [list(normalize_parameters(next_params).values())]))
            y_sample = np.append(y_sample, result['score'])

            logger.info(f"Trial {i} completed with score: {result['score']}")

            # Find and log the best parameters so far
            best_idx = np.argmax(y_sample)
            best_score = y_sample[best_idx]
            best_params = vector_to_parameters(X_sample[best_idx] * np.array([PARAM_SPACE[p]['max'] - PARAM_SPACE[p]['min'] for p in sorted(PARAM_SPACE.keys())]) + np.array([PARAM_SPACE[p]['min'] for p in sorted(PARAM_SPACE.keys())]))

            logger.info(f"Best score so far: {best_score} with parameters: {best_params}")
        else:
            logger.error(f"Trial {i} failed")

    # Final report
    if len(y_sample) > 0:
        # Find the best observed parameters
        best_idx = np.argmax(y_sample)
        best_score = y_sample[best_idx]
        best_params = vector_to_parameters(X_sample[best_idx] * np.array([PARAM_SPACE[p]['max'] - PARAM_SPACE[p]['min'] for p in sorted(PARAM_SPACE.keys())]) + np.array([PARAM_SPACE[p]['min'] for p in sorted(PARAM_SPACE.keys())]))

        logger.info(f"Optimization completed. Best observed score: {best_score}")
        logger.info(f"Best observed parameters: {best_params}")

        # Predict the optimal parameters using the GP model
        bounds = [(0, 1) for _ in range(len(PARAM_SPACE))]
        optimal_params, predicted_score = predict_optimal_parameters(X_sample, y_sample, bounds)

        logger.info(f"Predicted optimal score: {predicted_score}")
        logger.info(f"Predicted optimal parameters: {optimal_params}")

        # Save best observed parameters to a separate file
        with open(os.path.join(RESULTS_DIR, "best_observed_parameters.json"), 'w') as f:
            json.dump({
                'score': float(best_score),
                'params': {k: float(v) if isinstance(v, (np.float32, np.float64)) else v
                          for k, v in best_params.items()}
            }, f, indent=2)

        # Save predicted optimal parameters to a separate file
        with open(os.path.join(RESULTS_DIR, "predicted_optimal_parameters.json"), 'w') as f:
            json.dump({
                'predicted_score': float(predicted_score),
                'params': {k: float(v) if isinstance(v, (np.float32, np.float64)) else v
                          for k, v in optimal_params.items()}
            }, f, indent=2)

        # For backward compatibility, save the best observed parameters as best_parameters.json
        with open(os.path.join(RESULTS_DIR, "best_parameters.json"), 'w') as f:
            json.dump({
                'score': float(best_score),
                'params': {k: float(v) if isinstance(v, (np.float32, np.float64)) else v
                          for k, v in best_params.items()}
            }, f, indent=2)
    else:
        logger.error("Optimization failed: No valid results obtained")

def plot_optimization_history(results_dir=None):
    """Plot the optimization history showing score improvement over trials."""
    if results_dir is None:
        results_dir = RESULTS_DIR

    # Load the CSV file with all trials
    csv_path = os.path.join(results_dir, "all_trials.csv")
    if not os.path.exists(csv_path):
        logger.error(f"CSV file not found: {csv_path}")
        return

    df = pd.read_csv(csv_path)

    # Sort by trial number
    df = df.sort_values('trial')

    # Create the plot
    plt.figure(figsize=(12, 8))

    # Plot score vs trial number
    plt.plot(df['trial'], df['score'], 'o-', linewidth=2, markersize=8)

    # Add a horizontal line at y=0
    plt.axhline(y=0, color='r', linestyle='--', alpha=0.5)

    # Highlight the best trial
    best_idx = df['score'].idxmax()
    best_trial = df.loc[best_idx]
    plt.scatter(best_trial['trial'], best_trial['score'], s=200, c='green',
                marker='*', edgecolors='black', zorder=10,
                label=f'Best Trial ({best_trial["trial"]})')

    # Add labels and title
    plt.xlabel('Trial Number', fontsize=14)
    plt.ylabel('Score', fontsize=14)
    plt.title('Optimization Progress', fontsize=16)
    plt.grid(True, alpha=0.3)
    plt.legend(fontsize=12)

    # Save the plot
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "optimization_history.png"))
    plt.close()

    logger.info(f"Optimization history plot saved to {os.path.join(results_dir, 'optimization_history.png')}")

def plot_parameter_importance(results_dir=None):
    """Plot the importance of each parameter based on correlation with score."""
    if results_dir is None:
        results_dir = RESULTS_DIR

    # Load the CSV file with all trials
    csv_path = os.path.join(results_dir, "all_trials.csv")
    if not os.path.exists(csv_path):
        logger.error(f"CSV file not found: {csv_path}")
        return

    df = pd.read_csv(csv_path)

    # Calculate correlation between parameters and score
    params = list(PARAM_SPACE.keys())
    correlations = []

    for param in params:
        if param in df.columns:
            corr = df[param].corr(df['score'])
            correlations.append((param, corr))

    # Sort by absolute correlation
    correlations.sort(key=lambda x: abs(x[1]), reverse=True)

    # Create the plot
    plt.figure(figsize=(12, 8))

    # Plot parameter importance
    param_names = [p[0] for p in correlations]
    corr_values = [p[1] for p in correlations]

    # Create horizontal bar chart
    bars = plt.barh(param_names, corr_values, color=['green' if c > 0 else 'red' for c in corr_values])

    # Add value labels
    for bar in bars:
        width = bar.get_width()
        label_x_pos = width + 0.01 if width > 0 else width - 0.01
        ha = 'left' if width > 0 else 'right'
        plt.text(label_x_pos, bar.get_y() + bar.get_height()/2, f'{width:.2f}',
                 va='center', ha=ha, fontsize=10)

    # Add labels and title
    plt.xlabel('Correlation with Score', fontsize=14)
    plt.ylabel('Parameter', fontsize=14)
    plt.title('Parameter Importance', fontsize=16)
    plt.grid(True, alpha=0.3)

    # Add a vertical line at x=0
    plt.axvline(x=0, color='black', linestyle='-', alpha=0.3)

    # Save the plot
    plt.tight_layout()
    plt.savefig(os.path.join(results_dir, "parameter_importance.png"))
    plt.close()

    logger.info(f"Parameter importance plot saved to {os.path.join(results_dir, 'parameter_importance.png')}")

def plot_best_trial_details(results_dir=None):
    """Create a detailed visualization of the best trial and predicted optimal parameters."""
    if results_dir is None:
        results_dir = RESULTS_DIR

    # Load the CSV file with all trials
    csv_path = os.path.join(results_dir, "all_trials.csv")
    if not os.path.exists(csv_path):
        logger.error(f"CSV file not found: {csv_path}")
        return

    df = pd.read_csv(csv_path)

    # Get the best trial
    best_idx = df['score'].idxmax()
    best_trial = df.loc[best_idx]

    # Load the predicted optimal parameters if available
    predicted_optimal_path = os.path.join(results_dir, "predicted_optimal_parameters.json")
    has_predicted_optimal = os.path.exists(predicted_optimal_path)

    if has_predicted_optimal:
        with open(predicted_optimal_path, 'r') as f:
            predicted_optimal = json.load(f)

    # Create figure with subplots
    fig = plt.figure(figsize=(14, 12))  # Increased height to accommodate parameter comparison

    if has_predicted_optimal:
        gs = gridspec.GridSpec(3, 2, width_ratios=[1, 1], height_ratios=[1, 1, 1])
    else:
        gs = gridspec.GridSpec(2, 2, width_ratios=[1, 1], height_ratios=[1, 1])

    # 1. Parameter values for best trial
    ax1 = plt.subplot(gs[0, 0])
    params = list(PARAM_SPACE.keys())
    param_values = [best_trial[p] for p in params]

    # Create horizontal bar chart
    ax1.barh(params, param_values, color='skyblue')
    ax1.set_title(f'Parameters for Best Trial (Trial {best_trial["trial"]})', fontsize=14)

    # Add parameter values as text
    for i, v in enumerate(param_values):
        ax1.text(v + (max(param_values) * 0.02), i, str(v), va='center')

    # 2. Performance metrics (differences)
    ax2 = plt.subplot(gs[0, 1])
    metrics = ['execs_diff', 'paths_diff', 'crashes_diff', 'edges_diff', 'bitmap_diff']
    metric_labels = ['Executions/sec', 'Paths', 'Crashes', 'Edges', 'Bitmap Coverage']
    metric_values = [best_trial[m] for m in metrics]

    # Create bar chart with color based on value
    bars = ax2.bar(metric_labels, metric_values, color=['green' if v > 0 else 'red' for v in metric_values])
    ax2.set_title('Performance Metrics (% Difference from CFS)', fontsize=14)
    ax2.set_ylabel('Percent Difference (%)', fontsize=12)
    ax2.axhline(y=0, color='black', linestyle='-', alpha=0.3)

    # Add value labels
    for bar in bars:
        height = bar.get_height()
        label_y_pos = height + 1 if height > 0 else height - 1
        va = 'bottom' if height > 0 else 'top'
        ax2.text(bar.get_x() + bar.get_width()/2, label_y_pos, f'{height:.1f}%',
                ha='center', va=va, fontsize=10)

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
    score_components = {}
    for metric, weight in METRIC_WEIGHTS.items():
        score_components[metric] = best_trial[metric] * weight

    # Create pie chart of score components
    labels = [f'{m} ({v:.1f})' for m, v in score_components.items()]
    values = list(score_components.values())

    # Only include non-zero components
    non_zero_indices = [i for i, v in enumerate(values) if abs(v) > 0.1]
    non_zero_labels = [labels[i] for i in non_zero_indices]
    non_zero_values = [values[i] for i in non_zero_indices]

    if non_zero_values:
        ax4.pie(
            [abs(v) for v in non_zero_values],
            labels=non_zero_labels,
            autopct='%1.1f%%',
            startangle=90,
            colors=['green' if v > 0 else 'red' for v in non_zero_values]
        )
        ax4.set_title('Score Components', fontsize=14)
    else:
        ax4.text(0.5, 0.5, 'No significant score components',
                ha='center', va='center', fontsize=12)

    # 5. Parameter comparison (if predicted optimal parameters are available)
    if has_predicted_optimal:
        ax5 = plt.subplot(gs[2, :])  # Span both columns

        # Get parameter values
        best_values = [best_trial[p] for p in params]
        optimal_values = [predicted_optimal['params'][p] for p in params]

        # Set up the bar positions
        x = np.arange(len(params))
        width = 0.35

        # Create grouped bar chart
        ax5.bar(x - width/2, best_values, width, label='Best Observed', color='skyblue')
        ax5.bar(x + width/2, optimal_values, width, label='Predicted Optimal', color='orange')

        # Add labels and title
        ax5.set_xticks(x)
        ax5.set_xticklabels(params)
        ax5.set_title('Parameter Comparison: Best Observed vs. Predicted Optimal', fontsize=14)
        ax5.legend()

        # Add value labels
        for i, v in enumerate(best_values):
            ax5.text(i - width/2, v + max(best_values) * 0.02, str(int(v)), ha='center', va='bottom', fontsize=9)

        for i, v in enumerate(optimal_values):
            ax5.text(i + width/2, v + max(optimal_values) * 0.02, str(int(v)), ha='center', va='bottom', fontsize=9)

        # Add predicted score to the title
        predicted_score = predicted_optimal.get('predicted_score', 0)
        plt.suptitle(f'Best Trial (Score: {best_trial["score"]:.2f}) vs. Predicted Optimal (Score: {predicted_score:.2f})', fontsize=16)
    else:
        # Add overall title without predicted optimal
        plt.suptitle(f'Best Trial Details (Score: {best_trial["score"]:.2f})', fontsize=16)

    # Save the figure
    plt.tight_layout(rect=[0, 0, 1, 0.95])  # Adjust for the suptitle
    plt.savefig(os.path.join(results_dir, "best_trial_details.png"))
    plt.close()

    logger.info(f"Best trial details plot saved to {os.path.join(results_dir, 'best_trial_details.png')}")

def plot_parameter_heatmap(results_dir=None):
    """Create heatmaps showing the relationship between pairs of parameters and score."""
    if results_dir is None:
        results_dir = RESULTS_DIR

    # Load the CSV file with all trials
    csv_path = os.path.join(results_dir, "all_trials.csv")
    if not os.path.exists(csv_path):
        logger.error(f"CSV file not found: {csv_path}")
        return

    df = pd.read_csv(csv_path)

    # Get all parameter pairs
    params = list(PARAM_SPACE.keys())
    param_pairs = [(params[i], params[j]) for i in range(len(params)) for j in range(i+1, len(params))]

    # Create a figure with subplots for each parameter pair
    n_pairs = len(param_pairs)
    n_cols = 2
    n_rows = (n_pairs + n_cols - 1) // n_cols

    fig, axes = plt.subplots(n_rows, n_cols, figsize=(15, 5 * n_rows))
    axes = axes.flatten() if n_pairs > 1 else [axes]

    for i, (param1, param2) in enumerate(param_pairs):
        if i < len(axes):
            ax = axes[i]

            # Create scatter plot
            scatter = ax.scatter(df[param1], df[param2], c=df['score'],
                               cmap='viridis', s=100, alpha=0.7)

            # Highlight best trial
            best_idx = df['score'].idxmax()
            best_trial = df.loc[best_idx]
            ax.scatter(best_trial[param1], best_trial[param2], s=200, c='red',
                     marker='*', edgecolors='black', zorder=10)

            # Add labels
            ax.set_xlabel(param1, fontsize=10)
            ax.set_ylabel(param2, fontsize=10)
            ax.set_title(f'{param1} vs {param2}', fontsize=12)

            # Add colorbar
            plt.colorbar(scatter, ax=ax, label='Score')

    # Hide any unused subplots
    for j in range(i + 1, len(axes)):
        axes[j].axis('off')

    # Add overall title
    plt.suptitle('Parameter Relationships', fontsize=16)

    # Save the figure
    plt.tight_layout(rect=[0, 0, 1, 0.95])  # Adjust for the suptitle
    plt.savefig(os.path.join(results_dir, "parameter_heatmap.png"))
    plt.close()

    logger.info(f"Parameter heatmap saved to {os.path.join(results_dir, 'parameter_heatmap.png')}")

def generate_visualizations(results_dir=None):
    """Generate all visualizations for the optimization results."""
    if results_dir is None:
        results_dir = RESULTS_DIR

    logger.info(f"Generating visualizations for results in {results_dir}")

    plot_optimization_history(results_dir)
    plot_parameter_importance(results_dir)
    plot_best_trial_details(results_dir)
    plot_parameter_heatmap(results_dir)

    logger.info("All visualizations generated successfully")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Gaussian Process optimization for AFL++ scheduler parameters")
    parser.add_argument("--trials", type=int, default=DEFAULT_TRIALS,
                        help=f"Number of trials to run (default: {DEFAULT_TRIALS})")
    parser.add_argument("--duration", type=int, default=DEFAULT_DURATION,
                        help=f"Duration of each benchmark in minutes (default: {DEFAULT_DURATION})")
    parser.add_argument("--initial-samples", type=int, default=DEFAULT_INITIAL_SAMPLES,
                        help=f"Number of initial random samples (default: {DEFAULT_INITIAL_SAMPLES})")
    parser.add_argument("--replications", type=int, default=DEFAULT_REPLICATIONS,
                        help=f"Number of replications for each parameter combination (default: {DEFAULT_REPLICATIONS})")
    parser.add_argument("--visualize-only", action="store_true",
                        help="Only generate visualizations for the most recent results")
    parser.add_argument("--results-dir", type=str,
                        help="Specify a results directory to visualize (for --visualize-only)")

    args = parser.parse_args()

    if args.visualize_only:
        # Only generate visualizations
        if args.results_dir:
            generate_visualizations(args.results_dir)
        else:
            # Find the most recent results directory
            results_dirs = sorted(glob.glob("gp_optimization_results_*"), reverse=True)
            if results_dirs:
                generate_visualizations(results_dirs[0])
            else:
                logger.error("No results directories found")
    else:
        # Run the optimization
        main(
            n_trials=args.trials,
            duration=args.duration,
            initial_samples=args.initial_samples,
            replications=args.replications
        )

        # Generate visualizations after optimization
        generate_visualizations()
