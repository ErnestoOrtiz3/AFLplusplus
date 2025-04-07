/*
 * AFL++ CPU Scheduler - Monitoring Daemon
 * 
 * This component monitors AFL++ fuzzing instances and tracks their performance
 * to inform scheduling decisions.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <signal.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#define MAX_FUZZERS 1024
#define MAX_PATH 512
#define POLL_INTERVAL_MIN_MS 100   // Minimum polling interval (ms)
#define POLL_INTERVAL_MAX_MS 2000  // Maximum polling interval (ms)
#define POLL_INTERVAL_DEFAULT_MS 1000  // Default polling interval (ms)
#define WEIGHT_SCALE_FACTOR 10     // Maximum weight multiplier for best performer
#define MIN_WEIGHT_PERCENT 10      // Minimum weight as percentage of fair share
#define NEW_PATH_SCORE 100         // Score for finding a new path
#define NEW_CRASH_SCORE 500        // Score for finding a new crash
#define SCORE_DECAY_FACTOR 0.95    // Score decay per second
#define REBALANCE_INTERVAL_SEC 300 // Rebalance weights every 5 minutes

// Shared memory structure for communicating with the scheduler
typedef struct {
    uint32_t version;              // Protocol version
    uint32_t update_count;         // Number of updates
    uint64_t last_update_time;     // Timestamp of last update
    uint32_t fuzzer_count;         // Number of active fuzzers
    struct {
        pid_t pid;                 // Process ID
        uint32_t weight;           // Scheduling weight (1-1000)
        uint64_t last_path_time;   // Time of last new path
        uint64_t last_crash_time;  // Time of last new crash
    } fuzzers[MAX_FUZZERS];
} scheduler_shm_t;

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
} fuzzer_info_t;

// Global state
static volatile int running = 1;
static fuzzer_info_t fuzzers[MAX_FUZZERS];
static uint32_t fuzzer_count = 0;
static scheduler_shm_t *scheduler_shm = NULL;
static int shm_id = -1;
static uint32_t poll_interval_ms = POLL_INTERVAL_DEFAULT_MS;
static time_t last_rebalance_time = 0;

// Function prototypes
static void discover_afl_processes(void);
static void update_fuzzer_stats(void);
static void calculate_weights(void);
static void update_scheduler_shm(void);
static uint32_t count_files_in_dir(const char *dir_path, time_t *mtime);
static void parse_fuzzer_stats(fuzzer_info_t *fuzzer);
static void handle_signal(int sig);
static uint64_t get_current_time_ms(void);
static void cleanup(void);

int main(int argc, char *argv[]) {
    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-i") && i + 1 < argc) {
            poll_interval_ms = atoi(argv[i + 1]);
            if (poll_interval_ms < POLL_INTERVAL_MIN_MS) 
                poll_interval_ms = POLL_INTERVAL_MIN_MS;
            if (poll_interval_ms > POLL_INTERVAL_MAX_MS) 
                poll_interval_ms = POLL_INTERVAL_MAX_MS;
            i++;
        } else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("Usage: %s [-i poll_interval_ms]\n", argv[0]);
            return 0;
        }
    }

    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Create shared memory for communication with scheduler
    key_t key = ftok("/tmp", 'A');
    shm_id = shmget(key, sizeof(scheduler_shm_t), IPC_CREAT | 0666);
    if (shm_id == -1) {
        perror("shmget failed");
        return 1;
    }
    
    scheduler_shm = (scheduler_shm_t *)shmat(shm_id, NULL, 0);
    if (scheduler_shm == (void *)-1) {
        perror("shmat failed");
        return 1;
    }
    
    // Initialize shared memory
    memset(scheduler_shm, 0, sizeof(scheduler_shm_t));
    scheduler_shm->version = 1;
    
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
        
        // Update shared memory for scheduler
        update_scheduler_shm();
        
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
        char *out_flag = strstr(cmdline, " -o ");
        if (out_flag) {
            out_flag += 4;  // Skip " -o "
            out_dir = strdup(out_flag);
            // Find the end of the directory path
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
        
        // Skip if process is no longer active
        if (fuzzer->pid <= 0) {
            continue;
        }
        
        // Check if queue directory has been modified
        time_t queue_mtime = 0;
        uint32_t new_queue_count = count_files_in_dir(fuzzer->queue_dir, &queue_mtime);
        
        // Check if crashes directory has been modified
        time_t crashes_mtime = 0;
        uint32_t new_crashes_count = count_files_in_dir(fuzzer->crashes_dir, &crashes_mtime);
        
        // Detect new paths
        if (new_queue_count > fuzzer->queue_count) {
            uint32_t new_paths = new_queue_count - fuzzer->queue_count;
            printf("Fuzzer %s found %u new paths (total: %u)\n", 
                   fuzzer->fuzzer_id, new_paths, new_queue_count);
            
            // Update score based on new paths
            fuzzer->current_score += NEW_PATH_SCORE * new_paths;
            fuzzer->last_active = now;
            
            // Update scheduler shared memory
            for (uint32_t j = 0; j < scheduler_shm->fuzzer_count; j++) {
                if (scheduler_shm->fuzzers[j].pid == fuzzer->pid) {
                    scheduler_shm->fuzzers[j].last_path_time = now;
                    break;
                }
            }
        }
        
        // Detect new crashes
        if (new_crashes_count > fuzzer->crashes_count) {
            uint32_t new_crashes = new_crashes_count - fuzzer->crashes_count;
            printf("Fuzzer %s found %u new crashes (total: %u)\n", 
                   fuzzer->fuzzer_id, new_crashes, new_crashes_count);
            
            // Update score based on new crashes
            fuzzer->current_score += NEW_CRASH_SCORE * new_crashes;
            fuzzer->last_active = now;
            
            // Update scheduler shared memory
            for (uint32_t j = 0; j < scheduler_shm->fuzzer_count; j++) {
                if (scheduler_shm->fuzzers[j].pid == fuzzer->pid) {
                    scheduler_shm->fuzzers[j].last_crash_time = now;
                    break;
                }
            }
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

// Update shared memory for communication with the scheduler
static void update_scheduler_shm(void) {
    scheduler_shm->fuzzer_count = fuzzer_count;
    scheduler_shm->last_update_time = time(NULL);
    scheduler_shm->update_count++;
    
    for (uint32_t i = 0; i < fuzzer_count; i++) {
        scheduler_shm->fuzzers[i].pid = fuzzers[i].pid;
        scheduler_shm->fuzzers[i].weight = fuzzers[i].weight;
    }
}

// Count files in a directory and get its modification time
static uint32_t count_files_in_dir(const char *dir_path, time_t *mtime) {
    DIR *dir;
    struct dirent *entry;
    struct stat st;
    uint32_t count = 0;
    
    // Get directory modification time
    if (stat(dir_path, &st) == 0) {
        *mtime = st.st_mtime;
    } else {
        *mtime = 0;
        return 0;  // Directory doesn't exist or can't be accessed
    }
    
    // If directory hasn't been modified since last check, return cached count
    for (uint32_t i = 0; i < fuzzer_count; i++) {
        if (strcmp(dir_path, fuzzers[i].queue_dir) == 0) {
            if (*mtime <= fuzzers[i].dir_mtime_queue) {
                *mtime = fuzzers[i].dir_mtime_queue;
                return fuzzers[i].queue_count;
            }
            break;
        } else if (strcmp(dir_path, fuzzers[i].crashes_dir) == 0) {
            if (*mtime <= fuzzers[i].dir_mtime_crashes) {
                *mtime = fuzzers[i].dir_mtime_crashes;
                return fuzzers[i].crashes_count;
            }
            break;
        }
    }
    
    // Count files in directory
    dir = opendir(dir_path);
    if (!dir) {
        return 0;
    }
    
    while ((entry = readdir(dir)) != NULL) {
        // Skip . and ..
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        
        // Skip directories and special files
        char full_path[MAX_PATH];
        snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
        
        if (stat(full_path, &st) == 0 && S_ISREG(st.st_mode)) {
            count++;
        }
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
        snprintf(stats_path, sizeof(stats_path), "%s/%s/fuzzer_stats", 
                 fuzzer->out_dir, fuzzer->fuzzer_id);
    } else {
        snprintf(stats_path, sizeof(stats_path), "%s/fuzzer_stats", 
                 fuzzer->out_dir);
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

// Clean up resources
static void cleanup(void) {
    if (scheduler_shm != NULL && scheduler_shm != (void *)-1) {
        shmdt(scheduler_shm);
    }
    
    if (shm_id != -1) {
        shmctl(shm_id, IPC_RMID, NULL);
    }
    
    printf("AFL++ CPU Scheduler Monitor shut down\n");
}
