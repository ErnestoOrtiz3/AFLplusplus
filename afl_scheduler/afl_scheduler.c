#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <dirent.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "afl_scheduler.skel.h"

/* Structure that matches the AFL++ scheduler_feedback_t */
typedef struct scheduler_feedback {
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
} scheduler_feedback_t;

/* Global variables */
static struct afl_scheduler_bpf *skel = NULL;
static int fuzzer_performance_map_fd = -1;
static volatile sig_atomic_t running = 1;
static char metrics_dir[PATH_MAX] = "./scheduler_metrics";
static FILE *metrics_log = NULL;

/* Signal handler */
static void sig_handler(int sig)
{
    running = 0;
}

/* Get current time in milliseconds */
static unsigned long long get_current_time_ms(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (unsigned long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Initialize metrics logging */
static void init_metrics(const char *dir)
{
    char log_path[PATH_MAX];
    
    /* Create metrics directory if it doesn't exist */
    mkdir(dir, 0755);
    
    /* Open metrics log file */
    snprintf(log_path, sizeof(log_path), "%s/metrics_log.csv", dir);
    metrics_log = fopen(log_path, "w");
    if (!metrics_log) {
        fprintf(stderr, "Failed to open metrics log file: %s\n", strerror(errno));
        return;
    }
    
    /* Write CSV header */
    fprintf(metrics_log, "timestamp,pid,new_edges,total_edges,execs_per_sec,paths_found,unique_crashes,unique_hangs,queue_cycle,pending_favs,performance_score,weight\n");
    fflush(metrics_log);
}

/* Log metrics for a fuzzer */
static void log_metrics(pid_t pid, scheduler_feedback_t *feedback, unsigned int weight)
{
    if (!metrics_log) return;
    
    fprintf(metrics_log, "%llu,%d,%u,%u,%u,%u,%u,%u,%u,%u,%u,%u\n",
            get_current_time_ms(),
            pid,
            feedback->new_edges_found,
            feedback->total_edges_found,
            feedback->execs_per_sec,
            feedback->paths_found,
            feedback->unique_crashes,
            feedback->unique_hangs,
            feedback->queue_cycle,
            feedback->pending_favs,
            feedback->performance_score,
            weight);
    fflush(metrics_log);
}

/* Find AFL++ processes with scheduler feedback enabled */
static void scan_for_fuzzers(void)
{
    DIR *dir;
    struct dirent *entry;
    char path[PATH_MAX];
    char feedback_path[PATH_MAX];
    FILE *f;
    int shm_id;
    scheduler_feedback_t *feedback;
    
    /* Scan /proc for processes */
    dir = opendir("/proc");
    if (!dir) {
        fprintf(stderr, "Failed to open /proc: %s\n", strerror(errno));
        return;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        /* Skip non-numeric entries */
        if (!isdigit(entry->d_name[0])) continue;
        
        pid_t pid = atoi(entry->d_name);
        
        /* Check if this is an AFL++ process with scheduler feedback */
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        f = fopen(path, "r");
        if (!f) continue;
        
        char cmdline[4096] = {0};
        size_t len = fread(cmdline, 1, sizeof(cmdline) - 1, f);
        fclose(f);
        
        /* Replace null bytes with spaces for easier parsing */
        for (size_t i = 0; i < len; i++) {
            if (cmdline[i] == '\0') cmdline[i] = ' ';
        }
        
        /* Check if this is an AFL++ process */
        if (strstr(cmdline, "afl-fuzz") == NULL) continue;
        
        /* Check if scheduler feedback is enabled */
        char *out_dir = NULL;
        char *s = strstr(cmdline, " -o ");
        if (s) out_dir = s + 4;
        
        if (!out_dir) continue;
        
        /* Extract output directory */
        char out_dir_path[PATH_MAX] = {0};
        sscanf(out_dir, "%s", out_dir_path);
        
        /* Check for scheduler feedback file */
        char *instance_name = NULL;
        s = strstr(cmdline, " -S ");
        if (s) instance_name = s + 4;
        
        if (!instance_name) continue;
        
        /* Extract instance name */
        char instance_name_str[256] = {0};
        sscanf(instance_name, "%s", instance_name_str);
        
        /* Check if this is a scheduler instance */
        if (strcmp(instance_name_str, "scheduler") != 0) continue;
        
        /* Look for scheduler feedback file */
        snprintf(feedback_path, sizeof(feedback_path), "%s/%s/scheduler_feedback.txt", 
                 out_dir_path, instance_name_str);
        
        f = fopen(feedback_path, "r");
        if (!f) continue;
        
        /* Read shared memory ID */
        if (fscanf(f, "%d", &shm_id) != 1) {
            fclose(f);
            continue;
        }
        fclose(f);
        
        /* Attach to shared memory */
        feedback = (scheduler_feedback_t *)shmat(shm_id, NULL, SHM_RDONLY);
        if (feedback == (void *)-1) continue;
        
        /* Update BPF map with fuzzer stats */
        struct fuzzer_stats stats = {0};
        stats.pid = feedback->pid;
        stats.last_update_time = feedback->last_update_time;
        stats.new_edges_found = feedback->new_edges_found;
        stats.total_edges_found = feedback->total_edges_found;
        stats.execs_per_sec = feedback->execs_per_sec;
        stats.paths_found = feedback->paths_found;
        stats.unique_crashes = feedback->unique_crashes;
        stats.unique_hangs = feedback->unique_hangs;
        stats.queue_cycle = feedback->queue_cycle;
        stats.pending_favs = feedback->pending_favs;
        stats.performance_score = feedback->performance_score;
        
        /* Update BPF map */
        if (fuzzer_performance_map_fd >= 0) {
            unsigned int weight = 100;  /* Default weight */
            
            /* Calculate weight (same logic as in BPF program) */
            weight = 100;  /* Base weight */
            unsigned int bonus = 0;
            
            if (stats.new_edges_found > 0) {
                bonus += stats.new_edges_found * 20;
            }
            
            if (stats.unique_crashes > 0) {
                bonus += 50;
            }
            
            if (stats.execs_per_sec > 500) {
                bonus += 10;
            }
            
            bonus += stats.performance_score;
            
            unsigned long long time_since_update = get_current_time_ms() - stats.last_update_time;
            if (time_since_update > 5000) {
                bonus = bonus / 2;
            }
            
            weight += bonus;
            
            /* Update map */
            bpf_map_update_elem(fuzzer_performance_map_fd, &pid, &stats, BPF_ANY);
            
            /* Log metrics */
            log_metrics(pid, feedback, weight);
            
            printf("Updated fuzzer stats for PID %d (score: %u, weight: %u)\n", 
                   pid, stats.performance_score, weight);
        }
        
        /* Detach from shared memory */
        shmdt(feedback);
    }
    
    closedir(dir);
}

int main(int argc, char **argv)
{
    int err;
    
    /* Parse command line arguments */
    if (argc > 1) {
        strncpy(metrics_dir, argv[1], sizeof(metrics_dir) - 1);
    }
    
    /* Set up signal handlers */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    /* Initialize metrics logging */
    init_metrics(metrics_dir);
    
    /* Open BPF program */
    skel = afl_scheduler_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program\n");
        return 1;
    }
    
    /* Load and verify BPF program */
    err = afl_scheduler_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    /* Attach BPF program */
    err = afl_scheduler_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }
    
    /* Get map file descriptor */
    fuzzer_performance_map_fd = bpf_map__fd(skel->maps.fuzzer_performance);
    if (fuzzer_performance_map_fd < 0) {
        fprintf(stderr, "Failed to get map file descriptor\n");
        goto cleanup;
    }
    
    printf("AFL++ Scheduler loaded successfully\n");
    
    /* Main loop */
    while (running) {
        /* Scan for AFL++ fuzzer processes */
        scan_for_fuzzers();
        
        /* Sleep for a short time */
        sleep(1);
    }
    
    printf("Exiting...\n");
    
cleanup:
    /* Clean up */
    afl_scheduler_bpf__destroy(skel);
    if (metrics_log) fclose(metrics_log);
    
    return err != 0;
}
