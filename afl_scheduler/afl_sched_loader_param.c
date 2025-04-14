/*
 * AFL++ CPU Scheduler - BPF Loader with Configurable Parameters
 *
 * This component loads the BPF scheduler and pins its maps to the filesystem
 * so they can be accessed directly by the monitoring daemon.
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

/* Define types needed by the skeleton before including it */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef int s32;
typedef unsigned char u8;
typedef unsigned short u16;

/* Now include the skeleton header */
#include "afl_sched.skel.h"

// Default values
#define DEFAULT_BOOST_DURATION_US 1000000  // 1 second boost after finding something
#define DEFAULT_SLICE_US 20000             // Default time slice in microseconds
#define DEFAULT_SLICE_MIN_US 5000          // Minimum time slice in microseconds

// BPF filesystem directory
#define BPF_FS_DIR "/sys/fs/bpf/afl_scheduler"

// Map paths
#define WEIGHTS_MAP_PATH BPF_FS_DIR "/afl_weights"
#define BOOST_MAP_PATH BPF_FS_DIR "/afl_boost_until"

// Global state
static volatile int running = 1;
static struct afl_sched_bpf *skel = NULL;

// Configuration
static u64 boost_duration_us = DEFAULT_BOOST_DURATION_US;
static u64 slice_us = DEFAULT_SLICE_US;
static u64 slice_min_us = DEFAULT_SLICE_MIN_US;

// Function prototypes
static void handle_signal(int sig);
static int pin_maps(void);
static void cleanup(void);
static void print_usage(const char *prog_name);

int main(int argc, char *argv[]) {
    int err;
    int opt;
    
    // Parse command line arguments
    while ((opt = getopt(argc, argv, "b:s:m:h")) != -1) {
        switch (opt) {
            case 'b':
                boost_duration_us = atoll(optarg);
                if (boost_duration_us < 100000) { // Minimum 100ms
                    boost_duration_us = 100000;
                }
                break;
            case 's':
                slice_us = atoll(optarg);
                if (slice_us < 1000) { // Minimum 1ms
                    slice_us = 1000;
                }
                break;
            case 'm':
                slice_min_us = atoll(optarg);
                if (slice_min_us < 1000) { // Minimum 1ms
                    slice_min_us = 1000;
                }
                if (slice_min_us > slice_us) {
                    slice_min_us = slice_us;
                }
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
    
    // Create BPF filesystem directory if it doesn't exist
    if (mkdir(BPF_FS_DIR, 0700) && errno != EEXIST) {
        fprintf(stderr, "Failed to create BPF filesystem directory: %s\n", strerror(errno));
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
    skel->rodata->slice_us = slice_us;
    skel->rodata->slice_us_min = slice_min_us;
    skel->rodata->prio_boost_duration_us = boost_duration_us;
    
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
    
    // Pin maps to the filesystem
    err = pin_maps();
    if (err) {
        fprintf(stderr, "Failed to pin maps: %s\n", strerror(-err));
        cleanup();
        return 1;
    }
    
    printf("AFL++ CPU Scheduler loaded successfully\n");
    printf("Configuration:\n");
    printf("  Boost duration: %llu microseconds\n", boost_duration_us);
    printf("  Time slice: %llu microseconds\n", slice_us);
    printf("  Minimum time slice: %llu microseconds\n", slice_min_us);
    printf("Maps pinned to:\n");
    printf("  Weights map: %s\n", WEIGHTS_MAP_PATH);
    printf("  Boost map: %s\n", BOOST_MAP_PATH);
    
    // Wait for signal to exit
    printf("Press Ctrl+C to unload the scheduler\n");
    while (running) {
        sleep(1);
    }
    
    cleanup();
    return 0;
}

// Print usage information
static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -b DURATION  Boost duration in microseconds (default: %u)\n", DEFAULT_BOOST_DURATION_US);
    printf("  -s SLICE     Time slice in microseconds (default: %u)\n", DEFAULT_SLICE_US);
    printf("  -m MIN_SLICE Minimum time slice in microseconds (default: %u)\n", DEFAULT_SLICE_MIN_US);
    printf("  -h           Show this help message\n");
}

// Pin maps to the filesystem
static int pin_maps(void) {
    int err;
    
    // Pin the weights map
    err = bpf_map__pin(skel->maps.afl_weights, WEIGHTS_MAP_PATH);
    if (err) {
        // If map already exists, unpin it first and try again
        if (errno == EEXIST) {
            unlink(WEIGHTS_MAP_PATH);
            err = bpf_map__pin(skel->maps.afl_weights, WEIGHTS_MAP_PATH);
        }
        if (err) {
            return err;
        }
    }
    
    // Pin the boost map
    err = bpf_map__pin(skel->maps.afl_boost_until, BOOST_MAP_PATH);
    if (err) {
        // If map already exists, unpin it first and try again
        if (errno == EEXIST) {
            unlink(BOOST_MAP_PATH);
            err = bpf_map__pin(skel->maps.afl_boost_until, BOOST_MAP_PATH);
        }
        if (err) {
            // Clean up the weights map if we fail
            bpf_map__unpin(skel->maps.afl_weights, WEIGHTS_MAP_PATH);
            return err;
        }
    }
    
    return 0;
}

// Signal handler
static void handle_signal(int sig) {
    printf("Received signal %d, shutting down...\n", sig);
    running = 0;
}

// Clean up resources
static void cleanup(void) {
    // Unpin maps if they exist
    unlink(WEIGHTS_MAP_PATH);
    unlink(BOOST_MAP_PATH);
    
    if (skel) {
        afl_sched_bpf__destroy(skel);
    }
    
    printf("AFL++ CPU Scheduler shut down\n");
}
