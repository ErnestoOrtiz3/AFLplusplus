/*
 * AFL++ CPU Scheduler - Userspace Component
 *
 * This component loads the BPF scheduler and communicates with the monitoring
 * daemon to update task weights.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "afl_sched.skel.h"

#define MAX_FUZZERS 1024
#define UPDATE_INTERVAL_MS 100
#define BOOST_DURATION_US 1000000  // 1 second boost after finding something

// Shared memory structure for communication with the monitoring daemon
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

// Global state
static volatile int running = 1;
static struct afl_sched_bpf *skel = NULL;
static scheduler_shm_t *scheduler_shm = NULL;
static int shm_id = -1;
static uint32_t last_update_count = 0;

// Function prototypes
static void handle_signal(int sig);
static void update_weights(void);
static uint64_t get_current_time_us(void);
static void cleanup(void);

int main(int argc, char *argv[]) {
    int err;
    
    // Set up signal handlers
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // Connect to shared memory created by the monitoring daemon
    key_t key = ftok("/tmp", 'A');
    shm_id = shmget(key, sizeof(scheduler_shm_t), 0666);
    if (shm_id == -1) {
        fprintf(stderr, "Failed to connect to monitoring daemon shared memory: %s\n", 
                strerror(errno));
        fprintf(stderr, "Make sure the monitoring daemon is running\n");
        return 1;
    }
    
    scheduler_shm = (scheduler_shm_t *)shmat(shm_id, NULL, 0);
    if (scheduler_shm == (void *)-1) {
        perror("shmat failed");
        return 1;
    }
    
    // Load and verify BPF application
    skel = afl_sched_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        cleanup();
        return 1;
    }
    
    // Set configuration parameters
    skel->rodata->partial = false;
    skel->rodata->verbose = false;
    skel->rodata->slice_us = 20000;
    skel->rodata->slice_us_min = 5000;
    skel->rodata->prio_boost_duration_us = BOOST_DURATION_US;
    skel->rodata->shm_key = key;
    
    // Load and attach BPF programs
    err = afl_sched_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %s\n", strerror(errno));
        cleanup();
        return 1;
    }
    
    err = afl_sched_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton: %s\n", strerror(errno));
        cleanup();
        return 1;
    }
    
    printf("AFL++ CPU Scheduler loaded successfully\n");
    
    // Main loop: update weights based on monitoring daemon data
    while (running) {
        update_weights();
        usleep(UPDATE_INTERVAL_MS * 1000);
    }
    
    cleanup();
    return 0;
}

// Update task weights based on monitoring daemon data
static void update_weights(void) {
    uint32_t i;
    uint64_t now = get_current_time_us();
    
    // Check if monitoring daemon has updated the shared memory
    if (scheduler_shm->update_count == last_update_count) {
        return;
    }
    
    last_update_count = scheduler_shm->update_count;
    
    // Update weights for all active fuzzers
    for (i = 0; i < scheduler_shm->fuzzer_count; i++) {
        pid_t pid = scheduler_shm->fuzzers[i].pid;
        uint32_t weight = scheduler_shm->fuzzers[i].weight;
        
        if (pid <= 0) {
            continue;
        }
        
        // Update weight in BPF map
        bpf_map_update_elem(bpf_map__fd(skel->maps.afl_weights), &pid, &weight, BPF_ANY);
        
        // Check if this fuzzer recently found a new path or crash
        uint64_t last_path_time = scheduler_shm->fuzzers[i].last_path_time;
        uint64_t last_crash_time = scheduler_shm->fuzzers[i].last_crash_time;
        
        // Convert to microseconds for comparison with now
        uint64_t last_path_us = last_path_time * 1000000;
        uint64_t last_crash_us = last_crash_time * 1000000;
        
        // If a new path or crash was found recently, boost this fuzzer
        if (now - last_path_us < BOOST_DURATION_US || 
            now - last_crash_us < BOOST_DURATION_US) {
            
            // Set boost until timestamp
            uint64_t boost_until = now + BOOST_DURATION_US;
            bpf_map_update_elem(bpf_map__fd(skel->maps.afl_boost_until), 
                               &pid, &boost_until, BPF_ANY);
            
            printf("Boosting fuzzer PID %d until %lu\n", pid, boost_until);
        }
    }
}

// Signal handler
static void handle_signal(int sig) {
    printf("Received signal %d, shutting down...\n", sig);
    running = 0;
}

// Get current time in microseconds
static uint64_t get_current_time_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000 + (uint64_t)ts.tv_nsec / 1000;
}

// Clean up resources
static void cleanup(void) {
    if (skel) {
        afl_sched_bpf__destroy(skel);
    }
    
    if (scheduler_shm != NULL && scheduler_shm != (void *)-1) {
        shmdt(scheduler_shm);
    }
    
    printf("AFL++ CPU Scheduler shut down\n");
}
