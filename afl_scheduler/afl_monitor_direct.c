/*
 * AFL++ CPU Scheduler - Monitoring Daemon (Direct BPF Map Access)
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
#define POLL_INTERVAL_DEFAULT_MS 1000
#define POLL_INTERVAL_MIN_MS 100
#define POLL_INTERVAL_MAX_MS 2000
#define REBALANCE_INTERVAL_SEC 300
#define NEW_PATH_SCORE 100.0
#define NEW_CRASH_SCORE 500.0
#define SCORE_DECAY_FACTOR 0.99
#define WEIGHT_SCALE_FACTOR 10.0
#define MIN_WEIGHT_PERCENT 10

// BPF filesystem directory
#define BPF_FS_DIR "/sys/fs/bpf/afl_scheduler"

// Map paths
#define WEIGHTS_MAP_PATH BPF_FS_DIR "/afl_weights"
#define BOOST_MAP_PATH BPF_FS_DIR "/afl_boost_until"

// Boost duration in microseconds
#define BOOST_DURATION_US 1000000  // 1 second boost after finding something

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
static uint32_t poll_interval_ms = POLL_INTERVAL_DEFAULT_MS;
static time_t last_rebalance_time = 0;

// BPF map file descriptors
static int weights_map_fd = -1;
static int boost_map_fd = -1;

// Function prototypes
static void discover_afl_processes(void);
static void update_fuzzer_stats(void);
static void calculate_weights(void);
static void update_bpf_maps(void);
static uint32_t count_files_in_dir(const char *dir_path, time_t *mtime);
static void parse_fuzzer_stats(fuzzer_info_t *fuzzer);
static void handle_signal(int sig);
static uint64_t get_current_time_ms(void);
static uint64_t get_current_time_us(void);
static void cleanup(void);

int main(int argc, char *argv[]) {
    int opt;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "i:h")) != -1) {
        switch (opt) {
            case 'i':
                poll_interval_ms = atoi(optarg);
                if (poll_interval_ms < POLL_INTERVAL_MIN_MS) {
                    poll_interval_ms = POLL_INTERVAL_MIN_MS;
                } else if (poll_interval_ms > POLL_INTERVAL_MAX_MS) {
                    poll_interval_ms = POLL_INTERVAL_MAX_MS;
                }
                break;
            case 'h':
                printf("Usage: %s [-i poll_interval_ms]\n", argv[0]);
                printf("  -i poll_interval_ms: Polling interval in milliseconds (default: %d, min: %d, max: %d)\n",
                       POLL_INTERVAL_DEFAULT_MS, POLL_INTERVAL_MIN_MS, POLL_INTERVAL_MAX_MS);
                printf("  -h: Show this help message\n");
                return 0;
            default:
                fprintf(stderr, "Usage: %s [-i poll_interval_ms]\n", argv[0]);
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
    
    printf("AFL++ CPU Scheduler Monitor started (poll interval: %u ms)\n", 
           poll_interval_ms);
    
    // Main monitoring loop
    while (running) {
        uint64_t start_time = get_current_time_ms();
        
        // Discover AFL++ processes
        discover_afl_processes();
        
        // Update fuzzer statistics
        update_fuzzer_stats();
        
        // Calculate weights based on performance
        calculate_weights();
        
        // Update BPF maps directly
        update_bpf_maps();
        
        // Periodic rebalancing
        time_t now = time(NULL);
        if (now - last_rebalance_time > REBALANCE_INTERVAL_SEC) {
            printf("Performing periodic rebalance of weights\n");
            // Partial reset of scores to prevent getting stuck
            for (uint32_t i = 0; i < fuzzer_count; i++) {
                fuzzers[i].current_score *= 0.5;  // Reduce scores by half
            }
            last_rebalance_time = now;
        }
        
        // Adaptive sleep to maintain consistent polling interval
        uint64_t elapsed = get_current_time_ms() - start_time;
        if (elapsed < poll_interval_ms) {
            usleep((poll_interval_ms - elapsed) * 1000);
        }
    }
    
    cleanup();
    return 0;
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
        
        // Check queue directory for new paths
        time_t queue_mtime;
        uint32_t new_queue_count = count_files_in_dir(fuzzer->queue_dir, &queue_mtime);
        
        // Check crashes directory for new crashes
        time_t crashes_mtime;
        uint32_t new_crashes_count = count_files_in_dir(fuzzer->crashes_dir, &crashes_mtime);
        
        // Detect new paths
        if (new_queue_count > fuzzer->queue_count) {
            uint32_t new_paths = new_queue_count - fuzzer->queue_count;
            printf("Fuzzer %s found %u new paths (total: %u)\n", 
                   fuzzer->fuzzer_id, new_paths, new_queue_count);
            
            // Update score based on new paths
            fuzzer->current_score += NEW_PATH_SCORE * new_paths;
            fuzzer->last_active = now;
            fuzzer->last_path_time = now;
        }
        
        // Detect new crashes
        if (new_crashes_count > fuzzer->crashes_count) {
            uint32_t new_crashes = new_crashes_count - fuzzer->crashes_count;
            printf("Fuzzer %s found %u new crashes (total: %u)\n", 
                   fuzzer->fuzzer_id, new_crashes, new_crashes_count);
            
            // Update score based on new crashes
            fuzzer->current_score += NEW_CRASH_SCORE * new_crashes;
            fuzzer->last_active = now;
            fuzzer->last_crash_time = now;
        }
        
        // Update counts
        fuzzer->queue_count = new_queue_count;
        fuzzer->crashes_count = new_crashes_count;
        fuzzer->dir_mtime_queue = queue_mtime;
        fuzzer->dir_mtime_crashes = crashes_mtime;
        
        // Parse fuzzer_stats file for additional metrics
        parse_fuzzer_stats(fuzzer);
        
        // Apply score decay
        float time_since_last_check = (float)(now - fuzzer->last_active);
        if (time_since_last_check > 0) {
            // Apply exponential decay based on time since last activity
            float decay = powf(SCORE_DECAY_FACTOR, time_since_last_check);
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
        
        // Calculate weight: base_weight * (1 + (WEIGHT_SCALE_FACTOR - 1) * relative_score)
        // This gives a range from base_weight to base_weight * WEIGHT_SCALE_FACTOR
        uint32_t weight = base_weight * (1.0 + (WEIGHT_SCALE_FACTOR - 1.0) * relative_score);
        
        // Ensure minimum weight
        uint32_t min_weight = (base_weight * MIN_WEIGHT_PERCENT) / 100;
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
            if (fuzzers[i].weight < MIN_WEIGHT_PERCENT) {
                fuzzers[i].weight = MIN_WEIGHT_PERCENT;
            }
        }
    }
}

// Update BPF maps directly
static void update_bpf_maps(void) {
    uint64_t now = get_current_time_us();
    
    for (uint32_t i = 0; i < fuzzer_count; i++) {
        pid_t pid = fuzzers[i].pid;
        uint32_t weight = fuzzers[i].weight;
        
        if (pid <= 0) {
            continue;
        }
        
        // Update weight in BPF map
        bpf_map_update_elem(weights_map_fd, &pid, &weight, BPF_ANY);
        
        // Check if this fuzzer recently found a new path or crash
        time_t last_path_time = fuzzers[i].last_path_time;
        time_t last_crash_time = fuzzers[i].last_crash_time;
        
        // Convert to microseconds for comparison with now
        uint64_t last_path_us = last_path_time * 1000000;
        uint64_t last_crash_us = last_crash_time * 1000000;
        
        // If a new path or crash was found recently, boost this fuzzer
        if (now - last_path_us < BOOST_DURATION_US || 
            now - last_crash_us < BOOST_DURATION_US) {
            
            // Set boost until timestamp
            uint64_t boost_until = now + BOOST_DURATION_US;
            bpf_map_update_elem(boost_map_fd, &pid, &boost_until, BPF_ANY);
            
            printf("Boosting fuzzer PID %d until %lu\n", pid, boost_until);
        }
    }
}

// Count files in a directory and get its modification time
static uint32_t count_files_in_dir(const char *dir_path, time_t *mtime) {
    DIR *dir;
    struct dirent *entry;
    uint32_t count = 0;
    struct stat st;
    
    // Get directory modification time
    if (stat(dir_path, &st) == 0) {
        *mtime = st.st_mtime;
    } else {
        *mtime = 0;
    }
    
    // Open directory
    dir = opendir(dir_path);
    if (!dir) {
        return 0;
    }
    
    // Count files
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        // Skip directories
        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
        if (stat(full_path, &st) == 0 && S_ISDIR(st.st_mode)) {
            continue;
        }
        
        count++;
    }
    
    closedir(dir);
    return count;
}

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
