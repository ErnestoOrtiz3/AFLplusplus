/*
 * AFL++ Feedback-Guided CPU Scheduler Metrics
 * ------------------------------------------
 *
 * Copyright 2024 AFLplusplus Project. All rights reserved.
 *
 * This module collects and analyzes metrics about the scheduler's performance
 * to help evaluate its effectiveness.
 */

#include "scheduler_metrics.h"
#include <sys/time.h>

/* Get current time in milliseconds */
static unsigned long long get_current_time_ms() {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (unsigned long long)(tv.tv_sec) * 1000 + (unsigned long long)(tv.tv_usec) / 1000;
}

/* Format time as a string */
static void format_time(unsigned long long ms, char *buffer, size_t size) {
    time_t seconds = ms / 1000;
    struct tm *tm_info = localtime(&seconds);
    strftime(buffer, size, "%Y-%m-%d %H:%M:%S", tm_info);
}

/* Initialize the metrics collection */
scheduler_metrics_t* metrics_init(const char *output_dir) {
    scheduler_metrics_t *metrics = (scheduler_metrics_t*)malloc(sizeof(scheduler_metrics_t));
    if (!metrics) {
        perror("Failed to allocate memory for metrics");
        return NULL;
    }
    
    memset(metrics, 0, sizeof(scheduler_metrics_t));
    metrics->start_time = get_current_time_ms();
    metrics->last_dump = metrics->start_time;
    
    /* Create metrics directory */
    snprintf(metrics->metrics_dir, PATH_MAX, "%s/scheduler_metrics", output_dir);
    mkdir(metrics->metrics_dir, 0755);
    
    /* Open log file */
    char log_path[PATH_MAX];
    snprintf(log_path, PATH_MAX, "%s/metrics_log.csv", metrics->metrics_dir);
    metrics->metrics_log = fopen(log_path, "w");
    if (!metrics->metrics_log) {
        perror("Failed to open metrics log file");
        free(metrics);
        return NULL;
    }
    
    /* Write header to log file */
    fprintf(metrics->metrics_log, "timestamp,pid,total_edges,new_edges,crashes,new_crashes,weight,prioritized\n");
    
    /* Open summary file */
    char summary_path[PATH_MAX];
    snprintf(summary_path, PATH_MAX, "%s/summary.txt", metrics->metrics_dir);
    metrics->summary_file = fopen(summary_path, "w");
    if (!metrics->summary_file) {
        perror("Failed to open summary file");
        fclose(metrics->metrics_log);
        free(metrics);
        return NULL;
    }
    
    /* Initialize mutex */
    pthread_mutex_init(&metrics->metrics_mutex, NULL);
    
    printf("[+] Metrics collection initialized in %s\n", metrics->metrics_dir);
    return metrics;
}

/* Find a fuzzer in the metrics list */
static fuzzer_metrics_t* find_fuzzer(scheduler_metrics_t *metrics, pid_t pid) {
    fuzzer_metrics_t *current = metrics->fuzzers;
    while (current) {
        if (current->pid == pid) {
            return current;
        }
        current = current->next;
    }
    return NULL;
}

/* Record a new fuzzer being tracked */
void metrics_add_fuzzer(scheduler_metrics_t *metrics, pid_t pid, 
                        unsigned int total_edges, unsigned int crashes) {
    if (!metrics) return;
    
    pthread_mutex_lock(&metrics->metrics_mutex);
    
    /* Check if fuzzer already exists */
    if (find_fuzzer(metrics, pid)) {
        pthread_mutex_unlock(&metrics->metrics_mutex);
        return;
    }
    
    /* Create new fuzzer metrics */
    fuzzer_metrics_t *fuzzer = (fuzzer_metrics_t*)malloc(sizeof(fuzzer_metrics_t));
    if (!fuzzer) {
        perror("Failed to allocate memory for fuzzer metrics");
        pthread_mutex_unlock(&metrics->metrics_mutex);
        return;
    }
    
    memset(fuzzer, 0, sizeof(fuzzer_metrics_t));
    fuzzer->pid = pid;
    fuzzer->start_time = get_current_time_ms();
    fuzzer->last_update = fuzzer->start_time;
    fuzzer->total_edges_initial = total_edges;
    fuzzer->total_edges_current = total_edges;
    fuzzer->crashes_initial = crashes;
    fuzzer->crashes_current = crashes;
    fuzzer->lowest_weight = UINT_MAX;
    
    /* Add to linked list */
    fuzzer->next = metrics->fuzzers;
    metrics->fuzzers = fuzzer;
    
    metrics->total_processes++;
    metrics->active_processes++;
    
    /* Log the addition */
    char timestamp[64];
    format_time(fuzzer->start_time, timestamp, sizeof(timestamp));
    fprintf(metrics->metrics_log, "%s,%d,%u,0,%u,0,0,0\n", 
            timestamp, pid, total_edges, crashes);
    fflush(metrics->metrics_log);
    
    printf("[+] Started tracking fuzzer with PID %d (initial edges: %u, crashes: %u)\n", 
           pid, total_edges, crashes);
    
    pthread_mutex_unlock(&metrics->metrics_mutex);
}

/* Update metrics for a fuzzer */
void metrics_update_fuzzer(scheduler_metrics_t *metrics, pid_t pid,
                          unsigned int total_edges, unsigned int crashes,
                          unsigned int assigned_weight, int prioritized) {
    if (!metrics) return;
    
    pthread_mutex_lock(&metrics->metrics_mutex);
    
    fuzzer_metrics_t *fuzzer = find_fuzzer(metrics, pid);
    if (!fuzzer) {
        /* Fuzzer not found, add it */
        pthread_mutex_unlock(&metrics->metrics_mutex);
        metrics_add_fuzzer(metrics, pid, total_edges, crashes);
        return;
    }
    
    unsigned long long current_time = get_current_time_ms();
    unsigned int new_edges = 0;
    unsigned int new_crashes = 0;
    
    /* Calculate new edges and crashes */
    if (total_edges > fuzzer->total_edges_current) {
        new_edges = total_edges - fuzzer->total_edges_current;
        fuzzer->total_edges_gain += new_edges;
        fuzzer->total_edges_current = total_edges;
    }
    
    if (crashes > fuzzer->crashes_current) {
        new_crashes = crashes - fuzzer->crashes_current;
        fuzzer->crashes_gain += new_crashes;
        fuzzer->crashes_current = crashes;
    }
    
    /* Update scheduling metrics */
    if (prioritized) {
        fuzzer->times_prioritized++;
        
        /* Track correlation between prioritization and gains */
        if (new_edges > 0) {
            fuzzer->priority_to_edge_gain += new_edges;
        }
        
        if (new_crashes > 0) {
            fuzzer->priority_to_crash_gain += new_crashes;
        }
    }
    
    /* Update weight statistics */
    fuzzer->weight_sum += assigned_weight;
    fuzzer->weight_count++;
    
    if (assigned_weight > fuzzer->highest_weight) {
        fuzzer->highest_weight = assigned_weight;
    }
    
    if (assigned_weight < fuzzer->lowest_weight) {
        fuzzer->lowest_weight = assigned_weight;
    }
    
    /* Update last update time */
    fuzzer->last_update = current_time;
    
    /* Log the update */
    char timestamp[64];
    format_time(current_time, timestamp, sizeof(timestamp));
    fprintf(metrics->metrics_log, "%s,%d,%u,%u,%u,%u,%u,%d\n", 
            timestamp, pid, total_edges, new_edges, crashes, new_crashes, 
            assigned_weight, prioritized);
    fflush(metrics->metrics_log);
    
    /* Increment total scheduling decisions */
    metrics->total_scheduling_decisions++;
    
    pthread_mutex_unlock(&metrics->metrics_mutex);
    
    /* Check if we should dump metrics */
    if (current_time - metrics->last_dump >= 60000) { /* Every minute */
        metrics_periodic_dump(metrics);
    }
}

/* Remove a fuzzer from tracking (process ended) */
void metrics_remove_fuzzer(scheduler_metrics_t *metrics, pid_t pid) {
    if (!metrics) return;
    
    pthread_mutex_lock(&metrics->metrics_mutex);
    
    fuzzer_metrics_t *current = metrics->fuzzers;
    fuzzer_metrics_t *prev = NULL;
    
    while (current) {
        if (current->pid == pid) {
            /* Found the fuzzer to remove */
            if (prev) {
                prev->next = current->next;
            } else {
                metrics->fuzzers = current->next;
            }
            
            /* Log the removal */
            char timestamp[64];
            format_time(get_current_time_ms(), timestamp, sizeof(timestamp));
            fprintf(metrics->metrics_log, "%s,%d,REMOVED,0,0,0,0,0\n", timestamp, pid);
            
            printf("[+] Stopped tracking fuzzer with PID %d (final edges: %u, crashes: %u)\n", 
                   pid, current->total_edges_current, current->crashes_current);
            
            free(current);
            metrics->active_processes--;
            break;
        }
        
        prev = current;
        current = current->next;
    }
    
    pthread_mutex_unlock(&metrics->metrics_mutex);
}

/* Generate a metrics report */
void metrics_generate_report(scheduler_metrics_t *metrics) {
    if (!metrics) return;
    
    pthread_mutex_lock(&metrics->metrics_mutex);
    
    unsigned long long current_time = get_current_time_ms();
    unsigned long long runtime_ms = current_time - metrics->start_time;
    
    /* Create report file */
    char report_path[PATH_MAX];
    snprintf(report_path, PATH_MAX, "%s/report_%llu.txt", metrics->metrics_dir, current_time);
    FILE *report = fopen(report_path, "w");
    if (!report) {
        perror("Failed to open report file");
        pthread_mutex_unlock(&metrics->metrics_mutex);
        return;
    }
    
    /* Write report header */
    char start_time_str[64], current_time_str[64];
    format_time(metrics->start_time, start_time_str, sizeof(start_time_str));
    format_time(current_time, current_time_str, sizeof(current_time_str));
    
    fprintf(report, "AFL++ Feedback-Guided CPU Scheduler Metrics Report\n");
    fprintf(report, "===================================================\n\n");
    fprintf(report, "Start time: %s\n", start_time_str);
    fprintf(report, "Current time: %s\n", current_time_str);
    fprintf(report, "Runtime: %.2f hours\n\n", (double)runtime_ms / (1000.0 * 60.0 * 60.0));
    
    /* Overall statistics */
    fprintf(report, "Overall Statistics:\n");
    fprintf(report, "------------------\n");
    fprintf(report, "Total processes tracked: %u\n", metrics->total_processes);
    fprintf(report, "Currently active processes: %u\n", metrics->active_processes);
    fprintf(report, "Total scheduling decisions: %u\n", metrics->total_scheduling_decisions);
    fprintf(report, "\n");
    
    /* Per-fuzzer statistics */
    fprintf(report, "Per-Fuzzer Statistics:\n");
    fprintf(report, "--------------------\n");
    
    fuzzer_metrics_t *current = metrics->fuzzers;
    while (current) {
        fprintf(report, "PID %d:\n", current->pid);
        fprintf(report, "  Runtime: %.2f hours\n", 
                (double)(current_time - current->start_time) / (1000.0 * 60.0 * 60.0));
        
        /* Coverage and crashes */
        fprintf(report, "  Coverage:\n");
        fprintf(report, "    Initial edges: %u\n", current->total_edges_initial);
        fprintf(report, "    Current edges: %u\n", current->total_edges_current);
        fprintf(report, "    Total edges gained: %u\n", current->total_edges_gain);
        fprintf(report, "    Edge gain rate: %.2f edges/hour\n", 
                (double)current->total_edges_gain / 
                ((double)(current_time - current->start_time) / (1000.0 * 60.0 * 60.0)));
        
        fprintf(report, "  Crashes:\n");
        fprintf(report, "    Initial crashes: %u\n", current->crashes_initial);
        fprintf(report, "    Current crashes: %u\n", current->crashes_current);
        fprintf(report, "    Total crashes gained: %u\n", current->crashes_gain);
        
        /* Scheduling statistics */
        fprintf(report, "  Scheduling:\n");
        fprintf(report, "    Times prioritized: %u\n", current->times_prioritized);
        
        if (current->weight_count > 0) {
            fprintf(report, "    Average weight: %.2f\n", 
                    (double)current->weight_sum / (double)current->weight_count);
            fprintf(report, "    Highest weight: %u\n", current->highest_weight);
            fprintf(report, "    Lowest weight: %u\n", 
                    current->lowest_weight == UINT_MAX ? 0 : current->lowest_weight);
        }
        
        /* Correlation metrics */
        fprintf(report, "  Correlation:\n");
        fprintf(report, "    Edges gained after prioritization: %u\n", current->priority_to_edge_gain);
        fprintf(report, "    Crashes gained after prioritization: %u\n", current->priority_to_crash_gain);
        
        if (current->times_prioritized > 0) {
            fprintf(report, "    Edges per prioritization: %.2f\n", 
                    (double)current->priority_to_edge_gain / (double)current->times_prioritized);
            fprintf(report, "    Crashes per prioritization: %.2f\n", 
                    (double)current->priority_to_crash_gain / (double)current->times_prioritized);
        }
        
        fprintf(report, "\n");
        current = current->next;
    }
    
    /* Effectiveness analysis */
    fprintf(report, "Effectiveness Analysis:\n");
    fprintf(report, "----------------------\n");
    
    /* Calculate overall effectiveness metrics */
    unsigned int total_edges_gained = 0;
    unsigned int total_crashes_gained = 0;
    unsigned int total_priority_edge_gain = 0;
    unsigned int total_priority_crash_gain = 0;
    unsigned int total_prioritizations = 0;
    
    current = metrics->fuzzers;
    while (current) {
        total_edges_gained += current->total_edges_gain;
        total_crashes_gained += current->crashes_gain;
        total_priority_edge_gain += current->priority_to_edge_gain;
        total_priority_crash_gain += current->priority_to_crash_gain;
        total_prioritizations += current->times_prioritized;
        current = current->next;
    }
    
    fprintf(report, "Total edges gained across all fuzzers: %u\n", total_edges_gained);
    fprintf(report, "Total crashes gained across all fuzzers: %u\n", total_crashes_gained);
    
    if (total_prioritizations > 0) {
        fprintf(report, "Overall edges gained per prioritization: %.2f\n", 
                (double)total_priority_edge_gain / (double)total_prioritizations);
        fprintf(report, "Overall crashes gained per prioritization: %.2f\n", 
                (double)total_priority_crash_gain / (double)total_prioritizations);
        
        /* Calculate effectiveness ratio */
        double prioritization_ratio = (double)total_prioritizations / 
                                     (double)metrics->total_scheduling_decisions;
        double edge_gain_ratio = (double)total_priority_edge_gain / (double)total_edges_gained;
        
        fprintf(report, "Prioritization ratio: %.2f%%\n", prioritization_ratio * 100.0);
        fprintf(report, "Edge gain from prioritization: %.2f%%\n", edge_gain_ratio * 100.0);
        
        /* Effectiveness score (simple heuristic) */
        double effectiveness_score = edge_gain_ratio / prioritization_ratio;
        fprintf(report, "Scheduler effectiveness score: %.2f\n", effectiveness_score);
        
        /* Interpretation */
        fprintf(report, "\nInterpretation:\n");
        if (effectiveness_score > 1.5) {
            fprintf(report, "The scheduler appears to be HIGHLY EFFECTIVE at prioritizing productive fuzzers.\n");
        } else if (effectiveness_score > 1.0) {
            fprintf(report, "The scheduler appears to be EFFECTIVE at prioritizing productive fuzzers.\n");
        } else if (effectiveness_score > 0.5) {
            fprintf(report, "The scheduler appears to be SOMEWHAT EFFECTIVE at prioritizing productive fuzzers.\n");
        } else {
            fprintf(report, "The scheduler does not appear to be significantly more effective than random scheduling.\n");
        }
    }
    
    fclose(report);
    printf("[+] Generated metrics report: %s\n", report_path);
    
    pthread_mutex_unlock(&metrics->metrics_mutex);
}

/* Periodically dump metrics to disk */
void metrics_periodic_dump(scheduler_metrics_t *metrics) {
    if (!metrics) return;
    
    pthread_mutex_lock(&metrics->metrics_mutex);
    
    unsigned long long current_time = get_current_time_ms();
    metrics->last_dump = current_time;
    
    /* Update summary file */
    if (metrics->summary_file) {
        rewind(metrics->summary_file);
        ftruncate(fileno(metrics->summary_file), 0);
        
        fprintf(metrics->summary_file, "AFL++ Scheduler Metrics Summary\n");
        fprintf(metrics->summary_file, "==============================\n\n");
        
        char start_time_str[64], current_time_str[64];
        format_time(metrics->start_time, start_time_str, sizeof(start_time_str));
        format_time(current_time, current_time_str, sizeof(current_time_str));
        
        fprintf(metrics->summary_file, "Start time: %s\n", start_time_str);
        fprintf(metrics->summary_file, "Current time: %s\n", current_time_str);
        fprintf(metrics->summary_file, "Runtime: %.2f hours\n\n", 
                (double)(current_time - metrics->start_time) / (1000.0 * 60.0 * 60.0));
        
        fprintf(metrics->summary_file, "Active processes: %u / %u\n", 
                metrics->active_processes, metrics->total_processes);
        fprintf(metrics->summary_file, "Total scheduling decisions: %u\n\n", 
                metrics->total_scheduling_decisions);
        
        fprintf(metrics->summary_file, "Process Summary:\n");
        fprintf(metrics->summary_file, "---------------\n");
        fprintf(metrics->summary_file, "PID\tEdges\tGain\tCrashes\tPrioritized\tAvg Weight\n");
        
        fuzzer_metrics_t *current = metrics->fuzzers;
        while (current) {
            double avg_weight = 0.0;
            if (current->weight_count > 0) {
                avg_weight = (double)current->weight_sum / (double)current->weight_count;
            }
            
            fprintf(metrics->summary_file, "%d\t%u\t%u\t%u\t%u\t\t%.1f\n", 
                    current->pid, current->total_edges_current, current->total_edges_gain,
                    current->crashes_current, current->times_prioritized, avg_weight);
            
            current = current->next;
        }
        
        fflush(metrics->summary_file);
    }
    
    pthread_mutex_unlock(&metrics->metrics_mutex);
}

/* Clean up metrics collection */
void metrics_cleanup(scheduler_metrics_t *metrics) {
    if (!metrics) return;
    
    /* Generate final report */
    metrics_generate_report(metrics);
    
    pthread_mutex_lock(&metrics->metrics_mutex);
    
    /* Close files */
    if (metrics->metrics_log) {
        fclose(metrics->metrics_log);
    }
    
    if (metrics->summary_file) {
        fclose(metrics->summary_file);
    }
    
    /* Free fuzzer metrics */
    fuzzer_metrics_t *current = metrics->fuzzers;
    while (current) {
        fuzzer_metrics_t *next = current->next;
        free(current);
        current = next;
    }
    
    pthread_mutex_unlock(&metrics->metrics_mutex);
    pthread_mutex_destroy(&metrics->metrics_mutex);
    
    free(metrics);
    
    printf("[+] Metrics collection cleaned up\n");
}
