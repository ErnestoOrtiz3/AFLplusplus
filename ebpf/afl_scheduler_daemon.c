/*
 * AFL++ Feedback-Guided CPU Scheduler Daemon
 * -----------------------------------------
 *
 * Copyright 2024 AFLplusplus Project. All rights reserved.
 *
 * This daemon bridges AFL++ and the eBPF scheduler by:
 * 1. Finding AFL++ fuzzer processes
 * 2. Reading their performance metrics from shared memory
 * 3. Updating the eBPF maps with these metrics
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>
#include <ctype.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "scheduler_metrics.h"

/* Structure that matches the AFL++ scheduler_feedback_t */
typedef struct fuzzer_stats {
    pid_t pid;                  /* Process ID of this fuzzer */
    unsigned long long last_update_time;     /* Timestamp of last update (ms) */
    unsigned int new_edges_found;      /* New edges found since last update */
    unsigned int total_edges_found;    /* Total edges found by this fuzzer */
    unsigned int execs_per_sec;        /* Current execution speed */
    unsigned int paths_found;          /* Total paths discovered */
    unsigned int unique_crashes;       /* Number of unique crashes found */
    unsigned int unique_hangs;         /* Number of unique hangs found */
    unsigned int queue_cycle;          /* Current queue cycle */
    unsigned int pending_favs;         /* Number of pending favored paths */
    unsigned char performance_score;    /* Calculated performance score (0-100) */
    unsigned char reserved[3];          /* Padding for alignment */
} fuzzer_stats_t;

/* Global variables */
static int running = 1;
static int fuzzer_perf_map_fd = -1;
static struct bpf_object *obj = NULL;
static struct bpf_link *sched_link = NULL;
static scheduler_metrics_t *metrics = NULL;
static char output_dir[PATH_MAX] = "./scheduler_metrics";  /* Default output directory */

/* Signal handler for clean shutdown */
void handle_signal(int sig)
{
    printf("Received signal %d, shutting down...\n", sig);
    running = 0;
}

/* Find AFL++ fuzzer processes and their shared memory regions */
void scan_for_fuzzers(void)
{
    DIR *proc_dir;
    struct dirent *entry;
    char path[256];
    char cmdline[256];
    FILE *fp;

    proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("Failed to open /proc");
        return;
    }

    /* Scan all processes */
    while ((entry = readdir(proc_dir)) != NULL) {
        /* Skip non-numeric entries (not PIDs) */
        if (!isdigit(entry->d_name[0])) continue;

        /* Check if this is an AFL++ process */
        snprintf(path, sizeof(path), "/proc/%s/cmdline", entry->d_name);
        fp = fopen(path, "r");
        if (!fp) continue;

        if (fgets(cmdline, sizeof(cmdline), fp) != NULL) {
            /* Check if this is afl-fuzz */
            if (strstr(cmdline, "afl-fuzz")) {
                pid_t pid = atoi(entry->d_name);
                printf("Found AFL++ fuzzer with PID %d\n", pid);

                /* Look for scheduler feedback file in the output directory */
                char out_dir[256] = {0};
                int found_out_dir = 0;

                /* Reopen the cmdline file to parse arguments */
                fclose(fp);
                fp = fopen(path, "r");
                if (fp) {
                    char *arg = cmdline;
                    while (arg < cmdline + sizeof(cmdline)) {
                        if (*arg == '-' && *(arg+1) == 'o' && *(arg+2) == 0) {
                            /* Found -o option, next arg is output dir */
                            arg += strlen(arg) + 1;
                            if (arg < cmdline + sizeof(cmdline) && *arg) {
                                strncpy(out_dir, arg, sizeof(out_dir)-1);
                                found_out_dir = 1;
                                break;
                            }
                        }
                        arg += strlen(arg) + 1;
                        if (!*arg) break;
                    }
                    fclose(fp);
                }

                if (found_out_dir) {
                    /* Look for scheduler_feedback.txt in the output directory */
                    char feedback_path[512];
                    snprintf(feedback_path, sizeof(feedback_path), "%s/scheduler_feedback.txt", out_dir);

                    fp = fopen(feedback_path, "r");
                    if (fp) {
                        int shm_id;
                        if (fscanf(fp, "%d", &shm_id) == 1) {
                            printf("Found scheduler feedback SHM ID: %d for PID %d\n", shm_id, pid);

                            /* Attach to the shared memory */
                            fuzzer_stats_t *stats = (fuzzer_stats_t *)shmat(shm_id, NULL, SHM_RDONLY);
                            if (stats != (void *)-1) {
                                /* Update the eBPF map with the fuzzer stats */
                                if (fuzzer_perf_map_fd >= 0) {
                                    if (bpf_map_update_elem(fuzzer_perf_map_fd, &pid, stats, BPF_ANY) != 0) {
                                        perror("Failed to update eBPF map");
                                    } else {
                                        printf("Updated eBPF map for PID %d\n", pid);

                                        /* Calculate weight for this fuzzer */
                                        unsigned int weight = 100;  // Default weight
                                        if (stats->new_edges_found > 0) {
                                            weight += stats->new_edges_found * 20;
                                        }
                                        if (stats->unique_crashes > 0) {
                                            weight += 50;
                                        }
                                        if (stats->execs_per_sec > 500) {
                                            weight += 10;
                                        }
                                        weight += stats->performance_score;

                                        /* Determine if this fuzzer is being prioritized */
                                        int prioritized = (weight > 120) ? 1 : 0;

                                        /* Update metrics */
                                        if (metrics) {
                                            metrics_update_fuzzer(metrics, pid,
                                                                stats->total_edges_found,
                                                                stats->unique_crashes,
                                                                weight, prioritized);
                                        }
                                    }
                                }

                                /* Save output directory for metrics */
                                if (found_out_dir && metrics == NULL) {
                                    strncpy(output_dir, out_dir, sizeof(output_dir)-1);
                                    metrics = metrics_init(output_dir);
                                    if (!metrics) {
                                        fprintf(stderr, "Failed to initialize metrics collection\n");
                                    }
                                }

                                /* Detach from the shared memory */
                                shmdt(stats);
                            } else {
                                perror("Failed to attach to shared memory");
                            }
                        }
                        fclose(fp);
                    }
                }
            }
        }

        if (fp) fclose(fp);
    }

    closedir(proc_dir);
}

int main(int argc, char **argv)
{
    int err;

    /* Parse command line arguments */
    if (argc > 1) {
        strncpy(output_dir, argv[1], sizeof(output_dir)-1);
    }

    /* Set up signal handlers */
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    printf("AFL++ Scheduler Daemon starting...\n");

    /* Load the BPF program */
    obj = bpf_object__open("afl_scheduler.bpf.o");
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object\n");
        return 1;
    }

    /* Load the BPF program into the kernel */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %d\n", err);
        bpf_object__close(obj);
        return 1;
    }

    /* Get the file descriptor for the fuzzer performance map */
    struct bpf_map *map = bpf_object__find_map_by_name(obj, "fuzzer_performance");
    if (!map) {
        fprintf(stderr, "Failed to find fuzzer_performance map\n");
        bpf_object__close(obj);
        return 1;
    }
    fuzzer_perf_map_fd = bpf_map__fd(map);

    /* Attach the scheduler */
    struct bpf_program *prog;
    prog = bpf_object__find_program_by_name(obj, "afl_enqueue");
    if (!prog) {
        fprintf(stderr, "Failed to find afl_enqueue program\n");
        bpf_object__close(obj);
        return 1;
    }

    /* Attach the scheduler using sched_ext */
    sched_link = bpf_program__attach(prog);
    if (libbpf_get_error(sched_link)) {
        fprintf(stderr, "Failed to attach scheduler: %ld\n", libbpf_get_error(sched_link));
        fprintf(stderr, "Make sure you have loaded the sched_ext module: 'sudo modprobe sched_ext'\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("AFL++ Scheduler successfully attached\n");
    printf("Press Ctrl+C to detach and exit\n");

    /* Initialize metrics collection */
    metrics = metrics_init(output_dir);
    if (!metrics) {
        fprintf(stderr, "Failed to initialize metrics collection\n");
    } else {
        printf("Metrics collection initialized in %s\n", output_dir);
    }

    /* Main loop */
    unsigned long report_interval = 0;
    while (running) {
        /* Scan for AFL++ fuzzer processes */
        scan_for_fuzzers();

        /* Generate metrics report periodically (every 5 minutes) */
        if (metrics && ++report_interval >= 300) {
            metrics_generate_report(metrics);
            report_interval = 0;
        }

        /* Sleep for a short time */
        sleep(1);
    }

    /* Clean up */
    printf("Detaching scheduler...\n");
    bpf_link__destroy(sched_link);
    bpf_object__close(obj);

    /* Clean up metrics collection */
    if (metrics) {
        printf("Generating final metrics report...\n");
        metrics_generate_report(metrics);
        metrics_cleanup(metrics);
    }

    printf("AFL++ Scheduler daemon stopped\n");

    return 0;
}
