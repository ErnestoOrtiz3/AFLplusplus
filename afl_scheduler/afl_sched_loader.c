/*
 * AFL++ CPU Scheduler - BPF Loader
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

#define BOOST_DURATION_US 1000000  // 1 second boost after finding something

// BPF filesystem directory
#define BPF_FS_DIR "/sys/fs/bpf/afl_scheduler"

// Map paths
#define WEIGHTS_MAP_PATH BPF_FS_DIR "/afl_weights"
#define BOOST_MAP_PATH BPF_FS_DIR "/afl_boost_until"

// Global state
static volatile int running = 1;
static struct afl_sched_bpf *skel = NULL;

// Function prototypes
static void handle_signal(int sig);
static int pin_maps(void);
static void cleanup(void);

int main(int argc, char *argv[]) {
    int err;
    
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
    skel->rodata->slice_us = 20000;
    skel->rodata->slice_us_min = 5000;
    skel->rodata->prio_boost_duration_us = BOOST_DURATION_US;
    
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
