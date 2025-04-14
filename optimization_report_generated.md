# AFL++ Scheduler Parameter Optimization Report

Date: 2025-04-14 10:34:05

Number of trials: 20


## Best Parameters

Score: 3195.12

Parameters:
- boost_duration: 500000
- boost_weight: 600
- boost_decay: 5000000
- slice_us: 10000
- slice_min_us: 2000

Metrics:
- Paths difference: 46.38%
- Crashes difference: 283.33%
- Edges difference: 13.99%
- Bitmap coverage difference: 6.94pp
- Executions/sec difference: 81.12%

## Top 5 Configurations

### Rank 1 (Score: 3195.12)

Parameters:
- boost_duration: 500000
- boost_weight: 600
- boost_decay: 5000000
- slice_us: 10000
- slice_min_us: 2000

Metrics:
- Paths difference: 46.38%
- Crashes difference: 283.33%
- Edges difference: 13.99%
- Bitmap coverage difference: 6.94pp
- Executions/sec difference: 81.12%


### Rank 2 (Score: 1324.86)

Parameters:
- boost_duration: 500000
- boost_weight: 700
- boost_decay: 1500000
- slice_us: 30000
- slice_min_us: 4000

Metrics:
- Paths difference: 7.64%
- Crashes difference: 125.00%
- Edges difference: 11.48%
- Bitmap coverage difference: 4.91pp
- Executions/sec difference: -1.03%


### Rank 3 (Score: 1307.50)

Parameters:
- boost_duration: 1000000
- boost_weight: 800
- boost_decay: 5000000
- slice_us: 10000
- slice_min_us: 1000

Metrics:
- Paths difference: -13.05%
- Crashes difference: 142.86%
- Edges difference: -14.79%
- Bitmap coverage difference: -8.48pp
- Executions/sec difference: -0.83%


### Rank 4 (Score: 1135.94)

Parameters:
- boost_duration: 2000000
- boost_weight: 1700
- boost_decay: 2500000
- slice_us: 45000
- slice_min_us: 9000

Metrics:
- Paths difference: -24.96%
- Crashes difference: 133.33%
- Edges difference: -20.30%
- Bitmap coverage difference: -10.75pp
- Executions/sec difference: 0.29%


### Rank 5 (Score: 871.90)

Parameters:
- boost_duration: 1000000
- boost_weight: 2600
- boost_decay: 3000000
- slice_us: 15000
- slice_min_us: 10000

Metrics:
- Paths difference: -5.63%
- Crashes difference: 88.89%
- Edges difference: 2.46%
- Bitmap coverage difference: 1.23pp
- Executions/sec difference: 2.54%


## Parameter Analysis

### boost_duration:
- Range in top 5: 500000 to 2000000
- Average in top 5: 1000000.00
- Values in top 5: [500000, 500000, 1000000, 2000000, 1000000]

### boost_weight:
- Range in top 5: 600 to 2600
- Average in top 5: 1280.00
- Values in top 5: [600, 700, 800, 1700, 2600]

### boost_decay:
- Range in top 5: 1500000 to 5000000
- Average in top 5: 3400000.00
- Values in top 5: [5000000, 1500000, 5000000, 2500000, 3000000]

### slice_us:
- Range in top 5: 10000 to 45000
- Average in top 5: 22000.00
- Values in top 5: [10000, 30000, 10000, 45000, 15000]

### slice_min_us:
- Range in top 5: 1000 to 10000
- Average in top 5: 5200.00
- Values in top 5: [2000, 4000, 1000, 9000, 10000]


## All Trials

| Trial | Score | boost_duration | boost_weight | boost_decay | slice_us | slice_min_us | paths_diff | crashes_diff | edges_diff | bitmap_diff | execs_diff |
|-------|-------|---------------|--------------|-------------|----------|--------------|------------|--------------|------------|-------------|------------|
| 18 | 3195.12 | 500000 | 600 | 5000000 | 10000 | 2000 | 46.38% | 283.33% | 13.99% | 6.94pp | 81.12% |
| 14 | 1324.86 | 500000 | 700 | 1500000 | 30000 | 4000 | 7.64% | 125.00% | 11.48% | 4.91pp | -1.03% |
| 5 | 1307.50 | 1000000 | 800 | 5000000 | 10000 | 1000 | -13.05% | 142.86% | -14.79% | -8.48pp | -0.83% |
| 2 | 1135.94 | 2000000 | 1700 | 2500000 | 45000 | 9000 | -24.96% | 133.33% | -20.30% | -10.75pp | 0.29% |
| 1 | 871.90 | 1000000 | 2600 | 3000000 | 15000 | 10000 | -5.63% | 88.89% | 2.46% | 1.23pp | 2.54% |
| 12 | 869.04 | 1500000 | 1800 | 2500000 | 40000 | 5000 | 10.07% | 80.00% | 4.81% | 2.52pp | 1.51% |
| 9 | 599.95 | 3000000 | 200 | 3500000 | 5000 | 3000 | 12.34% | 50.00% | 11.38% | 5.22pp | -0.17% |
| 0 | 541.10 | 3500000 | 1500 | 4500000 | 25000 | 6000 | 5.21% | 50.00% | 4.31% | 2.46pp | -0.95% |
| 11 | 366.72 | 2000000 | 1500 | 2500000 | 50000 | 2000 | -13.77% | 50.00% | -17.62% | -9.09pp | -1.92% |
| 8 | 190.65 | 2500000 | 4000 | 4500000 | 15000 | 8000 | -7.27% | 23.53% | -1.53% | -0.80pp | -2.84% |
| 16 | 131.63 | 4000000 | 700 | 1500000 | 20000 | 5000 | 17.05% | 0.00% | 14.15% | 7.25pp | -3.67% |
| 17 | 108.84 | 1000000 | 2500 | 1500000 | 30000 | 3000 | 12.30% | 0.00% | 13.56% | 6.76pp | -0.06% |
| 7 | -123.97 | 500000 | 900 | 1500000 | 40000 | 1000 | 1.14% | -16.67% | 10.30% | 5.04pp | 1.31% |
| 13 | -247.54 | 2000000 | 5000 | 3500000 | 15000 | 1000 | -14.17% | -14.29% | -8.71% | -5.16pp | -0.89% |
| 10 | -329.93 | 5000000 | 100 | 1000000 | 5000 | 4000 | -21.08% | -16.67% | -16.67% | -8.36pp | 0.59% |
| 4 | -384.87 | 3000000 | 3800 | 4500000 | 35000 | 8000 | 13.48% | -46.67% | 3.84% | 2.09pp | 0.48% |
| 3 | -396.51 | 1000000 | 3400 | 4500000 | 50000 | 7000 | -5.69% | -35.71% | -2.92% | -1.48pp | -0.68% |
| 6 | -439.31 | 3000000 | 2500 | 4500000 | 25000 | 10000 | 4.63% | -47.62% | 3.80% | 2.09pp | -0.13% |
| 15 | -530.81 | 500000 | 900 | 500000 | 30000 | 3000 | 3.23% | -54.55% | -0.36% | -0.19pp | -0.17% |
| 19 | -1184.55 | 500000 | 2100 | 2000000 | 20000 | 4000 | -50.42% | -73.68% | -35.20% | -21.26pp | -61.47% |