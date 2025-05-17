/*
 * AFL++ CPU Scheduler - Monitoring Daemon with Configurable Parameters
 *
 * This daemon monitors AFL++ processes and updates BPF maps directly
 * to control the CPU scheduler.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <math.h>
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <bpf/bpf.h>

#define MAX_FUZZERS 1024
#define MAX_PATH 4096

// Default parameter values
#define POLL_INTERVAL_DEFAULT_MS 1000
#define POLL_INTERVAL_MIN_MS 100
#define POLL_INTERVAL_MAX_MS 5000
#define REBALANCE_INTERVAL_DEFAULT_SEC 300
#define NEW_PATH_SCORE_DEFAULT 100.0
#define NEW_CRASH_SCORE_DEFAULT 2000.0
#define SCORE_DECAY_FACTOR_DEFAULT 0.99
#define WEIGHT_SCALE_FACTOR_DEFAULT 10.0
#define MIN_WEIGHT_PERCENT_DEFAULT 10
#define BOOST_WEIGHT_DEFAULT 1000
#define BOOST_DURATION_DEFAULT_US 1000000  // 1 second boost after finding something

// BPF filesystem directory
#define BPF_FS_DIR "/sys/fs/bpf/afl_scheduler"

// Map paths
#define WEIGHTS_MAP_PATH BPF_FS_DIR "/afl_weights"
#define BOOST_MAP_PATH BPF_FS_DIR "/afl_boost_until"

// Fuzzer instance tracking structure
typedef struct {
    pid_t pid;                     // Process ID
    char fuzzer_id[64];            // Fuzzer ID (from -S flag)
    char out_dir[MAX_PATH];        // Output directory
    char queue_dir[MAX_PATH];      // Queue directory
    char crashes_dir[MAX_PATH];    // Crashes directory
    time_t last_queue_check;       // Last time queue was checked
    time_t last_crashes_check;     // Last time crashes were checked
    time_t dir_mtime_queue;        // Last modification time of queue dir
    time_t dir_mtime_crashes;      // Last modification time of crashes dir
    uint32_t queue_count;          // Number of files in queue
    uint32_t crashes_count;        // Number of crashes found
    uint32_t last_paths;           // Paths at last check
    uint32_t last_crashes;         // Crashes at last check
    uint32_t execs_per_sec;        // Current execution speed
    uint32_t cycle_done;           // Queue cycles completed
    float current_score;           // Current performance score
    uint32_t weight;               // Current scheduling weight
    time_t last_active;            // Last time fuzzer was active
    time_t start_time;             // When this fuzzer was first seen
    time_t last_path_time;         // Time of last new path
    time_t last_crash_time;        // Time of last new crash
} fuzzer_info_t;

// Global state
static volatile int running = 1;
static fuzzer_info_t fuzzers[MAX_FUZZERS];
static uint32_t fuzzer_count = 0;
static time_t last_rebalance_time = 0;

// BPF map file descriptors
static int weights_map_fd = -1;
static int boost_map_fd = -1;

// Configurable parameters
static uint32_t poll_interval_ms = POLL_INTERVAL_DEFAULT_MS;
static uint32_t rebalance_interval_sec = REBALANCE_INTERVAL_DEFAULT_SEC;
static float new_path_score = NEW_PATH_SCORE_DEFAULT;
static float new_crash_score = NEW_CRASH_SCORE_DEFAULT;
static float score_decay_factor = SCORE_DECAY_FACTOR_DEFAULT;
static float weight_scale_factor = WEIGHT_SCALE_FACTOR_DEFAULT;
static uint32_t min_weight_percent = MIN_WEIGHT_PERCENT_DEFAULT;
static uint32_t boost_weight = BOOST_WEIGHT_DEFAULT;
static uint64_t boost_duration_us = BOOST_DURATION_DEFAULT_US;
static int debug_mode = 0;

// Function prototypes
static void discover_afl_processes(void);
static void update_fuzzer_stats(void);
static void calculate_weights(void);
static void update_bpf_maps(void);
static void parse_fuzzer_stats(fuzzer_info_t *fuzzer);
static void handle_signal(int sig);
static uint64_t get_current_time_ms(void);
static uint64_t get_current_time_us(void);
static void cleanup(void);
static void print_usage(const char *prog_name);

int main(int argc, char *argv[]) {
    int opt;

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:r:p:c:d:w:m:b:t:Dh")) != -1) {
        switch (opt) {
            case 'i': // Poll interval
                poll_interval_ms = atoi(optarg);
                if (poll_interval_ms < POLL_INTERVAL_MIN_MS) {
                    poll_interval_ms = POLL_INTERVAL_MIN_MS;
                } else if (poll_interval_ms > POLL_INTERVAL_MAX_MS) {
                    poll_interval_ms = POLL_INTERVAL_MAX_MS;
                }
                break;
            case 'r': // Rebalance interval
                rebalance_interval_sec = atoi(optarg);
                break;
            case 'p': // New path score
                new_path_score = atof(optarg);
                break;
            case 'c': // New crash score
                new_crash_score = atof(optarg);
                break;
            case 'd': // Score decay factor
                score_decay_factor = atof(optarg);
                if (score_decay_factor < 0.5) score_decay_factor = 0.5;
                if (score_decay_factor > 0.999) score_decay_factor = 0.999;
                break;
            case 'w': // Weight scale factor
                weight_scale_factor = atof(optarg);
                if (weight_scale_factor < 1.0) weight_scale_factor = 1.0;
                break;
            case 'm': // Minimum weight percent
                min_weight_percent = atoi(optarg);
                if (min_weight_percent < 1) min_weight_percent = 1;
                if (min_weight_percent > 50) min_weight_percent = 50;
                break;
            case 'b': // Boost weight
                boost_weight = atoi(optarg);
                if (boost_weight < 100) boost_weight = 100;
                break;
            case 't': // Boost duration
                boost_duration_us = atoll(optarg);
                if (boost_duration_us < 100000) boost_duration_us = 100000; // Minimum 100ms
                break;
            case 'D': // Debug mode
                debug_mode = 1;
                printf("Debug mode enabled\n");
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);

    // Open BPF maps
    weights_map_fd = bpf_obj_get(WEIGHTS_MAP_PATH);
    if (weights_map_fd < 0) {
        fprintf(stderr, "Failed to open weights map: %s\n", strerror(errno));
        fprintf(stderr, "Make sure the BPF scheduler is loaded\n");
        return 1;
    }

    boost_map_fd = bpf_obj_get(BOOST_MAP_PATH);
    if (boost_map_fd < 0) {
        fprintf(stderr, "Failed to open boost map: %s\n", strerror(errno));
        close(weights_map_fd);
        return 1;
    }

    printf("AFL++ CPU Scheduler Monitor started with the following parameters:\n");
    printf("  Poll interval: %u ms\n", poll_interval_ms);
    printf("  Rebalance interval: %u sec\n", rebalance_interval_sec);
    printf("  New path score: %.1f\n", new_path_score);
    printf("  New crash score: %.1f\n", new_crash_score);
    printf("  Score decay factor: %.3f\n", score_decay_factor);
    printf("  Weight scale factor: %.1f\n", weight_scale_factor);
    printf("  Minimum weight percent: %u%%\n", min_weight_percent);
    printf("  Boost weight: %u\n", boost_weight);
    printf("  Boost duration: %lu us\n", boost_duration_us);

    // Main monitoring loop
    while (running) {
        uint64_t start_time = get_current_time_ms();

        // Discover AFL++ processes (still polling for new instances)
        discover_afl_processes();

        // Update fuzzer statistics (now only parses fuzzer_stats)
        update_fuzzer_stats();

        // Calculate weights based on performance
        calculate_weights();

        // Update BPF maps directly (now only updates weights)
        update_bpf_maps();

        // Periodic rebalancing
        time_t now = time(NULL);
        if (now - last_rebalance_time > rebalance_interval_sec) {
            printf("Performing periodic rebalance of weights\n");
            // Partial reset of scores to prevent getting stuck
            for (uint32_t i = 0; i < fuzzer_count; i++) {
                fuzzers[i].current_score *= 0.5;  // Reduce scores by half
            }
            last_rebalance_time = now;
        }

        // Adaptive sleep to maintain consistent polling interval
        // We can use a longer interval now since we're only polling for new instances
        uint64_t elapsed = get_current_time_ms() - start_time;
        if (elapsed < poll_interval_ms) {
            usleep((poll_interval_ms - elapsed) * 1000);
        }
    }

    cleanup();
    return 0;
}

// Print usage information
static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -i INTERVAL   Polling interval for discovering new AFL++ instances in milliseconds\n");
    printf("                (default: %u, min: %u, max: %u)\n",
           POLL_INTERVAL_DEFAULT_MS, POLL_INTERVAL_MIN_MS, POLL_INTERVAL_MAX_MS);
    printf("  -r INTERVAL   Rebalance interval in seconds (default: %u)\n",
           REBALANCE_INTERVAL_DEFAULT_SEC);
    printf("  -p SCORE      Score for finding a new path (default: %.1f)\n",
           NEW_PATH_SCORE_DEFAULT);
    printf("  -c SCORE      Score for finding a new crash (default: %.1f)\n",
           NEW_CRASH_SCORE_DEFAULT);
    printf("  -d FACTOR     Score decay factor (default: %.3f)\n",
           SCORE_DECAY_FACTOR_DEFAULT);
    printf("  -w FACTOR     Weight scale factor (default: %.1f)\n",
           WEIGHT_SCALE_FACTOR_DEFAULT);
    printf("  -m PERCENT    Minimum weight percentage (default: %u%%)\n",
           MIN_WEIGHT_PERCENT_DEFAULT);
    printf("  -b WEIGHT     Boost weight (default: %u)\n",
           BOOST_WEIGHT_DEFAULT);
    printf("  -t DURATION   Boost duration in microseconds (default: %u)\n",
           BOOST_DURATION_DEFAULT_US);
    printf("  -D            Enable debug mode\n");
    printf("  -h            Show this help message\n");
    printf("\nNote: Discovery events are now handled by the eBPF program directly.\n");
    printf("      This monitor only polls for new AFL++ instances and updates weights.\n");
}

// Discover AFL++ processes by scanning /proc
static void discover_afl_processes(void) {
    DIR *proc_dir;
    struct dirent *entry;
    char cmdline_path[MAX_PATH];
    char cmdline[4096];
    int fd;

    // Mark all fuzzers as potentially inactive
    for (uint32_t i = 0; i < fuzzer_count; i++) {
        fuzzers[i].pid = -1;  // Temporarily mark as inactive
    }

    proc_dir = opendir("/proc");
    if (!proc_dir) {
        perror("Failed to open /proc");
        return;
    }

    // Scan all processes
    while ((entry = readdir(proc_dir)) != NULL) {
        // Skip non-numeric entries (not PIDs)
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') {
            continue;
        }

        pid_t pid = atoi(entry->d_name);

        // Read command line
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
        fd = open(cmdline_path, O_RDONLY);
        if (fd == -1) {
            continue;  // Process may have terminated
        }

        ssize_t len = read(fd, cmdline, sizeof(cmdline) - 1);
        close(fd);

        if (len <= 0) {
            continue;
        }

        // Null-terminate and replace null bytes with spaces for easier parsing
        cmdline[len] = '\0';
        for (ssize_t i = 0; i < len - 1; i++) {
            if (cmdline[i] == '\0') {
                cmdline[i] = ' ';
            }
        }

        // Check if this is an AFL++ process
        if (strstr(cmdline, "afl-fuzz") == NULL) {
            continue;
        }

        // Extract output directory (-o flag)
        char *out_dir = NULL;
        char *o_flag = strstr(cmdline, " -o ");
        if (o_flag) {
            o_flag += 4;  // Skip " -o "
            out_dir = strdup(o_flag);
            // Find the end of the output directory
            char *end = out_dir;
            while (*end && *end != ' ') {
                end++;
            }
            *end = '\0';
        }

        // Extract fuzzer ID (-S flag)
        char *fuzzer_id = NULL;
        char *s_flag = strstr(cmdline, " -S ");
        if (s_flag) {
            s_flag += 4;  // Skip " -S "
            fuzzer_id = strdup(s_flag);
            // Find the end of the fuzzer ID
            char *end = fuzzer_id;
            while (*end && *end != ' ') {
                end++;
            }
            *end = '\0';
        } else {
            // Check for -M flag (main node)
            char *m_flag = strstr(cmdline, " -M ");
            if (m_flag) {
                m_flag += 4;  // Skip " -M "
                fuzzer_id = strdup(m_flag);
                // Find the end of the fuzzer ID
                char *end = fuzzer_id;
                while (*end && *end != ' ') {
                    end++;
                }
                *end = '\0';
            }
        }

        // If we found both output directory and fuzzer ID
        if (out_dir && fuzzer_id) {
            // Check if we already know this fuzzer
            int found = 0;
            for (uint32_t i = 0; i < fuzzer_count; i++) {
                if (strcmp(fuzzers[i].fuzzer_id, fuzzer_id) == 0 &&
                    strcmp(fuzzers[i].out_dir, out_dir) == 0) {
                    // Update PID if changed
                    fuzzers[i].pid = pid;
                    fuzzers[i].last_active = time(NULL);
                    found = 1;
                    break;
                }
            }

            // If this is a new fuzzer
            if (!found && fuzzer_count < MAX_FUZZERS) {
                fuzzer_info_t *fuzzer = &fuzzers[fuzzer_count];
                memset(fuzzer, 0, sizeof(fuzzer_info_t));

                fuzzer->pid = pid;
                strncpy(fuzzer->fuzzer_id, fuzzer_id, sizeof(fuzzer->fuzzer_id) - 1);
                strncpy(fuzzer->out_dir, out_dir, sizeof(fuzzer->out_dir) - 1);

                // Construct paths to queue and crashes directories
                if (fuzzer_id[0]) {
                    snprintf(fuzzer->queue_dir, sizeof(fuzzer->queue_dir),
                             "%s/%s/queue", out_dir, fuzzer_id);
                    snprintf(fuzzer->crashes_dir, sizeof(fuzzer->crashes_dir),
                             "%s/%s/crashes", out_dir, fuzzer_id);
                } else {
                    snprintf(fuzzer->queue_dir, sizeof(fuzzer->queue_dir),
                             "%s/queue", out_dir);
                    snprintf(fuzzer->crashes_dir, sizeof(fuzzer->crashes_dir),
                             "%s/crashes", out_dir);
                }

                fuzzer->start_time = fuzzer->last_active = time(NULL);
                fuzzer->weight = 100;  // Default weight

                printf("Discovered new AFL++ instance: PID=%d, ID=%s, Dir=%s\n",
                       pid, fuzzer_id, out_dir);

                fuzzer_count++;
            }
        }

        // Free allocated memory
        if (out_dir) free(out_dir);
        if (fuzzer_id) free(fuzzer_id);
    }

    closedir(proc_dir);

    // Remove inactive fuzzers
    for (uint32_t i = 0; i < fuzzer_count; i++) {
        if (fuzzers[i].pid == -1) {
            // Check if the process is truly gone
            char proc_path[MAX_PATH];
            snprintf(proc_path, sizeof(proc_path), "/proc/%d", fuzzers[i].pid);
            if (access(proc_path, F_OK) == -1) {
                // Process is gone, remove it from our list
                printf("AFL++ instance terminated: PID=%d, ID=%s\n",
                       fuzzers[i].pid, fuzzers[i].fuzzer_id);

                // Remove by shifting remaining entries
                if (i < fuzzer_count - 1) {
                    memmove(&fuzzers[i], &fuzzers[i + 1],
                            (fuzzer_count - i - 1) * sizeof(fuzzer_info_t));
                }
                fuzzer_count--;
                i--;  // Recheck this index
            }
        }
    }
}

// Update statistics for all active fuzzers
static void update_fuzzer_stats(void) {
    time_t now = time(NULL);

    for (uint32_t i = 0; i < fuzzer_count; i++) {
        fuzzer_info_t *fuzzer = &fuzzers[i];

        // Skip inactive fuzzers
        if (fuzzer->pid <= 0) {
            continue;
        }

        // We no longer poll queue/ and crashes/ directories
        // Discovery events are now handled by the eBPF program
        // and boosts are applied directly

        // Parse fuzzer_stats file for additional metrics (execs_per_sec, cycles_done)
        parse_fuzzer_stats(fuzzer);

        // Apply score decay
        float time_since_last_check = (float)(now - fuzzer->last_active);
        if (time_since_last_check > 0) {
            // Apply exponential decay based on time since last activity
            float decay = powf(score_decay_factor, time_since_last_check);
            fuzzer->current_score *= decay;
        }
    }
}

// Calculate scheduling weights based on fuzzer performance
static void calculate_weights(void) {
    if (fuzzer_count == 0) {
        return;
    }

    // Find the highest score
    float max_score = 0.1;  // Avoid division by zero
    for (uint32_t i = 0; i < fuzzer_count; i++) {
        if (fuzzers[i].current_score > max_score) {
            max_score = fuzzers[i].current_score;
        }
    }

    // Calculate weights based on relative scores
    uint32_t base_weight = 100;  // Base weight for fair share
    uint32_t total_weight = 0;

    for (uint32_t i = 0; i < fuzzer_count; i++) {
        float relative_score = fuzzers[i].current_score / max_score;

        // Calculate weight: base_weight * (1 + (weight_scale_factor - 1) * relative_score)
        // This gives a range from base_weight to base_weight * weight_scale_factor
        uint32_t weight = base_weight * (1.0 + (weight_scale_factor - 1.0) * relative_score);

        // Ensure minimum weight
        uint32_t min_weight = (base_weight * min_weight_percent) / 100;
        if (weight < min_weight) {
            weight = min_weight;
        }

        fuzzers[i].weight = weight;
        total_weight += weight;
    }

    // Normalize weights to ensure they sum to fuzzer_count * 100
    uint32_t target_total = fuzzer_count * 100;
    if (total_weight > 0) {
        for (uint32_t i = 0; i < fuzzer_count; i++) {
            fuzzers[i].weight = (fuzzers[i].weight * target_total) / total_weight;

            // Ensure minimum weight after normalization
            if (fuzzers[i].weight < min_weight_percent) {
                fuzzers[i].weight = min_weight_percent;
            }
        }
    }
}

// Update BPF maps directly
static void update_bpf_maps(void) {
    uint64_t now = get_current_time_us(); // Keep using this function to avoid unused warning

    for (uint32_t i = 0; i < fuzzer_count; i++) {
        pid_t pid = fuzzers[i].pid;
        uint32_t weight = fuzzers[i].weight;

        if (pid <= 0) {
            continue;
        }

        // Update weight in BPF map
        bpf_map_update_elem(weights_map_fd, &pid, &weight, BPF_ANY);

        // We no longer apply boosts here
        // Boosts are now applied directly by the eBPF program
        // when it receives discovery events

        // Just log the current time to avoid unused warning
        if (debug_mode) {
            printf("Current time: %lu\n", now);
        }
    }
}

// This function has been removed as we no longer poll directories
// Discovery events are now handled by the eBPF program directly

// Parse fuzzer_stats file for additional metrics
static void parse_fuzzer_stats(fuzzer_info_t *fuzzer) {
    char stats_path[MAX_PATH];
    FILE *f;
    char line[512];

    // Construct path to fuzzer_stats file
    if (fuzzer->fuzzer_id[0]) {
        if (snprintf(stats_path, sizeof(stats_path), "%s/%s/fuzzer_stats",
                 fuzzer->out_dir, fuzzer->fuzzer_id) >= sizeof(stats_path)) {
            fprintf(stderr, "Warning: stats_path truncated for fuzzer %s\n", fuzzer->fuzzer_id);
            return;
        }
    } else {
        if (snprintf(stats_path, sizeof(stats_path), "%s/fuzzer_stats",
                 fuzzer->out_dir) >= sizeof(stats_path)) {
            fprintf(stderr, "Warning: stats_path truncated\n");
            return;
        }
    }

    f = fopen(stats_path, "r");
    if (!f) {
        return;
    }

    while (fgets(line, sizeof(line), f)) {
        // Remove newline
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';

        // Parse execs_per_sec
        if (strncmp(line, "execs_per_sec", 13) == 0) {
            char *value = strchr(line, ':');
            if (value) {
                fuzzer->execs_per_sec = atoi(value + 1);
            }
        }

        // Parse cycles_done
        else if (strncmp(line, "cycles_done", 11) == 0) {
            char *value = strchr(line, ':');
            if (value) {
                uint32_t new_cycle = atoi(value + 1);
                if (new_cycle > fuzzer->cycle_done) {
                    // Completed a new cycle
                    fuzzer->cycle_done = new_cycle;
                    // Small score boost for completing a cycle
                    fuzzer->current_score += 10;
                }
            }
        }
    }

    fclose(f);
}

// Signal handler
static void handle_signal(int sig) {
    printf("Received signal %d, shutting down...\n", sig);
    running = 0;
}

// Get current time in milliseconds
static uint64_t get_current_time_ms(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return (uint64_t)tv.tv_sec * 1000 + (uint64_t)tv.tv_usec / 1000;
}

// Get current time in microseconds
static uint64_t get_current_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

// Clean up resources
static void cleanup(void) {
    // Close BPF map file descriptors
    if (weights_map_fd >= 0) {
        close(weights_map_fd);
    }

    if (boost_map_fd >= 0) {
        close(boost_map_fd);
    }

    printf("AFL++ CPU Scheduler Monitor shut down\n");
}
