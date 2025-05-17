/*
 * AFL++ CPU Scheduler - Enhanced BPF Loader (Simplified Version)
 *
 * This component loads the enhanced BPF scheduler and pins its maps to the filesystem
 * so they can be accessed directly by the monitoring daemon.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <errno.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/perf_event.h>
#include <linux/bpf.h>
#include <bpf/btf.h>

/* Define types needed by the skeleton before including it */
typedef unsigned long long u64;
typedef unsigned int u32;
typedef int s32;
typedef unsigned char u8;
typedef unsigned short u16;

/* Path to the AFL++ binary */
#define AFL_FUZZ_PATH "/home/ernesto/Documents/AFLplusplus/afl-fuzz"

/* Discovery event structure - must match the one in BPF program */
struct discovery_event {
    __u32 pid;           // Process ID that made the discovery
    __u64 timestamp;     // Timestamp of the discovery
    __u8 discovery_type; // 0 = path, 1 = crash, 2 = timeout
    __u8 saved;          // Return value from save_if_interesting (1 if saved, 0 if not)
};

/* Now include the skeleton header */
#include "afl_sched_enhanced_simple.skel.h"

// Default values
#define DEFAULT_BOOST_DURATION_US 1000000  // 1 second boost after finding something
#define DEFAULT_BOOST_WEIGHT 1000          // Weight during boost period
#define DEFAULT_SLICE_US 20000             // Default time slice in microseconds
#define DEFAULT_SLICE_MIN_US 5000          // Minimum time slice in microseconds
#define DEFAULT_BOOST_DECAY_PERIOD_US 2000000 // Period over which boost decays

// BPF filesystem directory
#define BPF_FS_DIR "/sys/fs/bpf/afl_scheduler"

// Map paths
#define WEIGHTS_MAP_PATH BPF_FS_DIR "/afl_weights"
#define BOOST_MAP_PATH BPF_FS_DIR "/afl_boost_until"

// Global state
static volatile int running = 1;
static struct afl_sched_enhanced_simple_bpf *skel = NULL;
static struct perf_buffer *pb = NULL;
static int perf_buffer_pages = 8; // Number of pages for perf buffer

// Configuration
static u64 boost_duration_us = DEFAULT_BOOST_DURATION_US;
static u32 boost_weight = DEFAULT_BOOST_WEIGHT;
static u64 slice_us = DEFAULT_SLICE_US;
static u64 slice_min_us = DEFAULT_SLICE_MIN_US;
static u64 boost_decay_period_us = DEFAULT_BOOST_DECAY_PERIOD_US;

// Function prototypes
static void handle_signal(int sig);
static int pin_maps(void);
static void cleanup(void);
static void print_usage(const char *prog_name);
static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz);
static void handle_lost_events(void *ctx, int cpu, unsigned long long lost);

int main(int argc, char *argv[]) {
    int err;
    int opt;

    // Parse command line arguments
    while ((opt = getopt(argc, argv, "b:w:s:m:d:h")) != -1) {
        switch (opt) {
            case 'b':
                boost_duration_us = strtoull(optarg, NULL, 10);
                if (boost_duration_us < 100000) { // Minimum 100ms
                    boost_duration_us = 100000;
                }
                break;
            case 'w':
                boost_weight = strtoul(optarg, NULL, 10);
                if (boost_weight < 100) { // Minimum weight
                    boost_weight = 100;
                }
                break;
            case 's':
                slice_us = strtoull(optarg, NULL, 10);
                if (slice_us < 1000) { // Minimum 1ms
                    slice_us = 1000;
                }
                break;
            case 'm':
                slice_min_us = strtoull(optarg, NULL, 10);
                if (slice_min_us < 1000) { // Minimum 1ms
                    slice_min_us = 1000;
                }
                if (slice_min_us > slice_us) {
                    slice_min_us = slice_us;
                }
                break;
            case 'd':
                boost_decay_period_us = strtoull(optarg, NULL, 10);
                if (boost_decay_period_us < 100000) { // Minimum 100ms
                    boost_decay_period_us = 100000;
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
    skel = afl_sched_enhanced_simple_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        cleanup();
        return 1;
    }

    // Set the BPF_F_SLEEPABLE flag for the init program only
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, skel->obj) {
        const char *prog_name = bpf_program__name(prog);
        if (prog_name && strcmp(prog_name, "afl_sched_init") == 0) {
            bpf_program__set_flags(prog, BPF_F_SLEEPABLE);
            printf("Set BPF_F_SLEEPABLE flag for afl_sched_init program\n");
        }
    }

    // Set configuration parameters
    skel->rodata->partial = false;
    skel->rodata->verbose = false;
    skel->rodata->slice_us = slice_us;
    skel->rodata->slice_us_min = slice_min_us;
    skel->rodata->prio_boost_duration_us = boost_duration_us;
    skel->rodata->boost_weight = boost_weight;
    skel->rodata->boost_decay_period_us = boost_decay_period_us;

    // Load and attach BPF programs
    err = afl_sched_enhanced_simple_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton: %s\n", strerror(errno));
        cleanup();
        return 1;
    }

    // Only attach the scheduler operations, not the uretprobe
    // We'll manually attach the uretprobe later
    skel->links.afl_sched_ops = bpf_map__attach_struct_ops(skel->maps.afl_sched_ops);
    if (!skel->links.afl_sched_ops) {
        fprintf(stderr, "Failed to attach struct_ops: %s\n", strerror(errno));
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

    printf("\n==================================================\n");
    printf("🎯 AFL++ Enhanced CPU Scheduler (Simple) loaded successfully\n");
    printf("==================================================\n");
    printf("📊 Configuration:\n");
    printf("  ⏱️  Boost duration: %llu microseconds\n", (unsigned long long)boost_duration_us);
    printf("  ⚖️  Boost weight: %u\n", boost_weight);
    printf("  📉 Boost decay period: %llu microseconds\n", (unsigned long long)boost_decay_period_us);
    printf("  ⏲️  Time slice: %llu microseconds\n", (unsigned long long)slice_us);
    printf("  ⏲️  Minimum time slice: %llu microseconds\n", (unsigned long long)slice_min_us);
    printf("\n📍 Maps pinned to:\n");
    printf("  📊 Weights map: %s\n", WEIGHTS_MAP_PATH);
    printf("  🚀 Boost map: %s\n", BOOST_MAP_PATH);
    printf("\n🔄 Direct BPF boosting enabled (microsecond latency)\n");
    printf("==================================================\n");

    // We'll attach the uretprobe when AFL++ starts running
    // For now, just set up the perf buffer to receive events
    printf("Note: The uretprobe will be attached when AFL++ starts running\n");

    // Set up perf buffer for discovery events
    pb = perf_buffer__new(bpf_map__fd(skel->maps.discovery_events),
                         perf_buffer_pages,
                         handle_event,
                         handle_lost_events,
                         NULL, /* ctx */
                         NULL);
    if (!pb) {
        fprintf(stderr, "Failed to create perf buffer: %s\n", strerror(errno));
        cleanup();
        return 1;
    }
    printf("Waiting for discovery events...\n");

    // Wait for signal to exit
    printf("Press Ctrl+C to unload the scheduler\n");

    // Flag to track if we've attached the uretprobe
    bool uretprobe_attached = false;

    while (running) {
        // Poll for events with a timeout of 100ms
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-err));
            break;
        }

        // Check if AFL++ is running and attach uretprobe if needed
        // Only check every 5 seconds to avoid excessive checking
        static time_t last_check_time = 0;
        time_t current_time = time(NULL);

        if (!uretprobe_attached && (current_time - last_check_time >= 5)) {
            last_check_time = current_time;
            // Check if AFL++ binary exists
            if (access(AFL_FUZZ_PATH, F_OK) == 0) {
                // Check if any AFL++ processes are running
                FILE *fp;
                char cmd[256];
                snprintf(cmd, sizeof(cmd), "pgrep -f afl-fuzz");
                fp = popen(cmd, "r");
                if (fp) {
                    char line[256];
                    if (fgets(line, sizeof(line), fp) && atoi(line) > 0) {
                        // AFL++ is running, try to attach uretprobe
                        printf("Detected AFL++ running (PID %d), attaching uretprobe...\n", atoi(line));

                        // Find the offset of save_if_interesting function
                        FILE *nm_fp;
                        char nm_cmd[256];
                        char nm_line[256];
                        unsigned long offset = 0;

                        // Use nm to find the symbol offset
                        snprintf(nm_cmd, sizeof(nm_cmd), "nm -D %s | grep save_if_interesting", AFL_FUZZ_PATH);
                        nm_fp = popen(nm_cmd, "r");
                        if (nm_fp) {
                            if (fgets(nm_line, sizeof(nm_line), nm_fp)) {
                                // Parse the output (format: "address T symbol")
                                offset = strtoul(nm_line, NULL, 16);
                                printf("Found save_if_interesting at offset 0x%lx\n", offset);
                            }
                            pclose(nm_fp);
                        }

                        if (offset > 0) {
                            // Count how many AFL++ instances are running
                            int afl_instance_count = 0;
                            FILE *count_fp;
                            char count_cmd[256];
                            snprintf(count_cmd, sizeof(count_cmd), "pgrep -f afl-fuzz | wc -l");
                            count_fp = popen(count_cmd, "r");
                            if (count_fp) {
                                char count_line[256];
                                if (fgets(count_line, sizeof(count_line), count_fp)) {
                                    afl_instance_count = atoi(count_line);
                                }
                                pclose(count_fp);
                            }

                            printf("Detected %d AFL++ instances running\n", afl_instance_count);

                            // Attach uretprobe to save_if_interesting function in ALL instances
                            // Using -1 as PID means it will attach to all processes using this binary
                            skel->links.trace_save_if_interesting_ret =
                                bpf_program__attach_uprobe(skel->progs.trace_save_if_interesting_ret,
                                                         true, /* this is a return probe */
                                                         -1, /* attach to all processes using this binary */
                                                         AFL_FUZZ_PATH,
                                                         offset);

                            if (skel->links.trace_save_if_interesting_ret) {
                                printf("\n========== URETPROBE ATTACHED SUCCESSFULLY ==========\n");
                                printf("✅ Attached uretprobe to save_if_interesting in all AFL++ instances\n");
                                printf("✅ Function offset: 0x%lx in %s\n", offset, AFL_FUZZ_PATH);
                                printf("✅ Monitoring %d AFL++ instances\n", afl_instance_count);
                                printf("✅ This will also apply to any new AFL++ instances that start later\n");
                                printf("✅ Direct BPF boosting is now active\n");
                                printf("========================================================\n\n");
                                uretprobe_attached = true;
                            } else {
                                fprintf(stderr, "\n❌ ERROR: Failed to attach uretprobe: %s\n", strerror(errno));
                                fprintf(stderr, "❌ Function offset: 0x%lx in %s\n", offset, AFL_FUZZ_PATH);
                                fprintf(stderr, "❌ Will retry in 5 seconds...\n\n");
                            }
                        }
                    }
                    pclose(fp);
                }
            }
        }
    }

    cleanup();
    return 0;
}

// Print usage information
static void print_usage(const char *prog_name) {
    printf("Usage: %s [options]\n", prog_name);
    printf("Options:\n");
    printf("  -b DURATION  Boost duration in microseconds (default: %llu)\n",
           (unsigned long long)DEFAULT_BOOST_DURATION_US);
    printf("  -w WEIGHT    Boost weight (default: %u)\n", DEFAULT_BOOST_WEIGHT);
    printf("  -d DECAY     Boost decay period in microseconds (default: %llu)\n",
           (unsigned long long)DEFAULT_BOOST_DECAY_PERIOD_US);
    printf("  -s SLICE     Time slice in microseconds (default: %llu)\n",
           (unsigned long long)DEFAULT_SLICE_US);
    printf("  -m MIN_SLICE Minimum time slice in microseconds (default: %llu)\n",
           (unsigned long long)DEFAULT_SLICE_MIN_US);
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

// Function removed - no longer needed since boost is applied directly in BPF

// Clean up resources
static void cleanup(void) {
    // Unpin maps if they exist
    unlink(WEIGHTS_MAP_PATH);
    unlink(BOOST_MAP_PATH);

    if (pb) {
        perf_buffer__free(pb);
        pb = NULL;
    }

    if (skel) {
        afl_sched_enhanced_simple_bpf__destroy(skel);
    }

    printf("AFL++ Enhanced CPU Scheduler (Simple) shut down\n");
}

// Handle discovery events from BPF program
static void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz) {
    struct discovery_event *event = data;
    char timestamp_str[64];
    time_t t;
    struct tm *tm;

    // Convert timestamp to human-readable format
    t = event->timestamp / 1000000000; // Convert ns to s
    tm = localtime(&t);
    strftime(timestamp_str, sizeof(timestamp_str), "%Y-%m-%d %H:%M:%S", tm);

    // Print event information
    printf("[%s] Discovery event from PID %u: ", timestamp_str, event->pid);
    if (event->discovery_type == 0) {
        printf("New path");
    } else if (event->discovery_type == 1) {
        printf("New crash");
    } else if (event->discovery_type == 2) {
        printf("New timeout");
    } else {
        printf("Unknown type (%u)", event->discovery_type);
    }
    printf(" (saved: %u)\n", event->saved);

    // Get the command line of the process to identify which AFL++ instance it is
    char cmd[256];
    char cmdline[1024] = {0};
    snprintf(cmd, sizeof(cmd), "ps -p %u -o cmd=", event->pid);
    FILE *fp = popen(cmd, "r");
    if (fp) {
        if (fgets(cmdline, sizeof(cmdline), fp)) {
            // Remove trailing newline
            cmdline[strcspn(cmdline, "\n")] = 0;
            printf("  Process: %s\n", cmdline);
        }
        pclose(fp);
    }

    // Boost is now applied directly in BPF for lower latency
    if (event->saved) {
        printf("\n🚀 DISCOVERY EVENT DETECTED 🚀\n");
        printf("🔍 PID %u made a discovery\n", event->pid);
        printf("🔍 Boost applied directly in BPF (microsecond latency)\n");
        printf("🔍 Process will receive higher scheduling priority\n");
        printf("🔍 Time: %s\n", timestamp_str);
        if (cmdline[0] != '\0') {
            printf("🔍 Process: %s\n", cmdline);
        }
        printf("------------------------------------------\n");
    }
}

// Handle lost events
static void handle_lost_events(void *ctx, int cpu, unsigned long long lost) {
    fprintf(stderr, "Lost %llu events on CPU #%d\n", lost, cpu);
}
