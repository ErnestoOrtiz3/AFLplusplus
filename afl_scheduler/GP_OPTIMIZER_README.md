# Gaussian Process-Based Bayesian Optimization for AFL++ Scheduler Parameters

This tool uses scikit-learn's Gaussian Process Regression to find optimal parameter settings for the AFL++ CPU scheduler by efficiently exploring the parameter space and learning from benchmark results.

## Overview

The optimizer works by:

1. Starting with random sampling to build an initial model
2. Training a Gaussian Process model on the results
3. Using Expected Improvement to select the next parameter combination to test
4. Running the benchmark with those parameters
5. Updating the model with the new results
6. Repeating until the budget of trials is exhausted

## Parameters Being Optimized

The optimizer tunes the following parameters:

- `boost_duration`: Duration of the boost period in microseconds (100,000 to 5,000,000)
- `boost_weight`: Weight assigned during boost period (100 to 5,000)
- `boost_decay`: Period over which boost decays in microseconds (500,000 to 5,000,000)
- `slice_us`: Time slice in microseconds (5,000 to 50,000)
- `slice_min_us`: Minimum time slice in microseconds (1,000 to 10,000)

## Requirements

- Python 3.6+
- scikit-learn
- numpy
- pandas
- matplotlib
- scipy

Install the required packages with:

```bash
pip install scikit-learn numpy pandas matplotlib scipy
```

## Usage

### Running the Optimizer

To run the optimizer with default settings:

```bash
sudo ./afl_scheduler/run_gp_optimization.sh
```

### Options

- `--trials N`: Number of trials to run (default: 30)
- `--duration N`: Duration of each benchmark in minutes (default: 10)
- `--initial-samples N`: Number of initial random samples (default: 10)
- `--replications N`: Number of replications for each parameter combination (default: 2)
- `--visualize-only`: Only generate visualizations for existing results
- `--results-dir DIR`: Specify a results directory to visualize (for --visualize-only)

Example with custom settings:

```bash
sudo ./afl_scheduler/run_gp_optimization.sh --trials 50 --duration 20 --initial-samples 15 --replications 3
```

### Visualizing Results Only

If you've already run the optimizer and just want to regenerate the visualizations:

```bash
sudo ./afl_scheduler/run_gp_optimization.sh --visualize-only
```

Or for a specific results directory:

```bash
sudo ./afl_scheduler/run_gp_optimization.sh --visualize-only --results-dir gp_optimization_results_20230501_123456
```

## Output

The optimizer creates a results directory with:

- `config.json`: Configuration used for the optimization
- `all_trials.csv`: CSV file with all trial results
- `trial_*.json`: Individual JSON files for each trial
- `best_parameters.json`: The best parameters found
- Visualization plots:
  - `optimization_history.png`: Score improvement over trials
  - `parameter_importance.png`: Correlation of parameters with score
  - `best_trial_details.png`: Detailed visualization of the best trial
  - `parameter_heatmap.png`: Relationships between parameter pairs

## Scoring and Noise Handling

The optimizer uses a composite score based on:

- Crashes found (highest weight)
- Paths discovered (high weight)
- Bitmap coverage (medium weight)
- Edges found (medium-low weight)
- Executions per second (low weight)

The score is calculated as a weighted sum of the percentage differences between the custom scheduler and the CFS scheduler.

### Noise Handling

To handle the inherent noise in fuzzing benchmarks, the optimizer:

1. **Runs multiple replications** of each parameter combination (default: 2)
2. **Averages the scores** across replications to get a more reliable estimate
3. **Shifts all scores** to positive values by adding a constant (500) to improve GP model stability
4. **Uses explicit noise modeling** in the Gaussian Process with a WhiteKernel component
5. **Tracks score variance** across replications to help identify unstable configurations

This approach helps the optimizer make more reliable decisions in the presence of noisy benchmark results.

## Advanced Usage

### Modifying the Parameter Space

To modify the parameter space, edit the `PARAM_SPACE` dictionary in `gp_optimizer.py`.

### Changing the Scoring Function

To change how trials are scored, modify the `calculate_score` function in `gp_optimizer.py`.

### Adjusting the GP Model

To adjust the Gaussian Process model, modify the kernel and other parameters in the `propose_next_parameters` function.
