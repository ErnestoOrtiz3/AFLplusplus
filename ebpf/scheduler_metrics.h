/*
 * AFL++ Feedback-Guided CPU Scheduler Metrics
 * ------------------------------------------
 *
 * Copyright 2024 AFLplusplus Project. All rights reserved.
 *
 * This module collects and analyzes metrics about the scheduler's performance
 * to help evaluate its effectiveness.
 */

#ifndef SCHEDULER_METRICS_H
#define SCHEDULER_METRICS_H

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

/* Structure to track metrics for a single fuzzer process */
typedef struct fuzzer_metrics {
    pid_t pid;                      /* Process ID */
    unsigned long long start_time;  /* When we started tracking this process */
    unsigned long long last_update; /* Last time metrics were updated */
    
    /* Performance metrics */
    unsigned int total_edges_initial;    /* Initial edge count when first seen */
    unsigned int total_edges_current;    /* Current edge count */
    unsigned int total_edges_gain;       /* Total edges gained while being tracked */
    unsigned int crashes_initial;        /* Initial crash count when first seen */
    unsigned int crashes_current;        /* Current crash count */
    unsigned int crashes_gain;           /* Total crashes gained while being tracked */
    
    /* Scheduling metrics */
    unsigned int times_prioritized;      /* Number of times this process was prioritized */
    unsigned int weight_sum;             /* Sum of all weights assigned */
    unsigned int weight_count;           /* Count of weight assignments */
    unsigned int highest_weight;         /* Highest weight ever assigned */
    unsigned int lowest_weight;          /* Lowest weight ever assigned */
    
    /* Correlation metrics */
    unsigned int priority_to_edge_gain;  /* Edges gained after prioritization */
    unsigned int priority_to_crash_gain; /* Crashes gained after prioritization */
    
    struct fuzzer_metrics *next;    /* Linked list for multiple fuzzers */
} fuzzer_metrics_t;

/* Structure for overall metrics collection */
typedef struct scheduler_metrics {
    char metrics_dir[PATH_MAX];     /* Directory to store metrics */
    FILE *metrics_log;              /* Log file for metrics */
    FILE *summary_file;             /* Summary file updated periodically */
    
    unsigned long long start_time;  /* When metrics collection started */
    unsigned long long last_dump;   /* Last time metrics were dumped to disk */
    
    /* Overall metrics */
    unsigned int total_processes;   /* Total number of processes tracked */
    unsigned int active_processes;  /* Currently active processes */
    unsigned int total_scheduling_decisions; /* Total scheduling decisions made */
    
    /* Fuzzer-specific metrics */
    fuzzer_metrics_t *fuzzers;      /* Linked list of fuzzer metrics */
    
    pthread_mutex_t metrics_mutex;  /* Mutex for thread-safe updates */
} scheduler_metrics_t;

/* Initialize the metrics collection */
scheduler_metrics_t* metrics_init(const char *output_dir);

/* Record a new fuzzer being tracked */
void metrics_add_fuzzer(scheduler_metrics_t *metrics, pid_t pid, 
                        unsigned int total_edges, unsigned int crashes);

/* Update metrics for a fuzzer */
void metrics_update_fuzzer(scheduler_metrics_t *metrics, pid_t pid,
                          unsigned int total_edges, unsigned int crashes,
                          unsigned int assigned_weight, int prioritized);

/* Remove a fuzzer from tracking (process ended) */
void metrics_remove_fuzzer(scheduler_metrics_t *metrics, pid_t pid);

/* Generate a metrics report */
void metrics_generate_report(scheduler_metrics_t *metrics);

/* Periodically dump metrics to disk */
void metrics_periodic_dump(scheduler_metrics_t *metrics);

/* Clean up metrics collection */
void metrics_cleanup(scheduler_metrics_t *metrics);

#endif /* SCHEDULER_METRICS_H */
