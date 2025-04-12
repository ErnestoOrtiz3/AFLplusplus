#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#define MAX_PIDS 1024

struct stats_record {
    time_t timestamp;
    int pid;
    u_int64_t total_boost_time;
    int is_boosted;
};

static int running = 1;
static int stats_fd = -1;
static int boost_until_fd = -1;
static int total_boost_time_fd = -1;
static char output_dir[256] = "./stats";

void sig_handler(int sig) {
    running = 0;
}

int main(int argc, char **argv) {
    int interval = 10; // Default 10 seconds
    
    // Parse args
    if (argc > 1) {
        interval = atoi(argv[1]);
    }
    if (argc > 2) {
        strncpy(output_dir, argv[2], sizeof(output_dir) - 1);
    }
    /* First argument (argv[1]): The interval in seconds between stats collection cycles. If not provided, it defaults to 10 seconds.
    Second argument (argv[2]): The output directory where the stats CSV files will be saved. If not provided, it defaults to "./stats". */
    
    
    // Open BPF maps
    stats_fd = bpf_obj_get("/sys/fs/bpf/afl_stats");
    boost_until_fd = bpf_obj_get("/sys/fs/bpf/afl_boost_until");
    total_boost_time_fd = bpf_obj_get("/sys/fs/bpf/afl_total_boost_time");
    
    if (stats_fd < 0 || boost_until_fd < 0 || total_boost_time_fd < 0) {
        fprintf(stderr, "Failed to open BPF maps: %s\n", strerror(errno));
        return 1;
    }
    
    // Setup signal handler
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Create output directory
    char cmd[300];
    snprintf(cmd, sizeof(cmd), "mkdir -p %s", output_dir);
    system(cmd);
    
    // Main collection loop
    while (running) {
        time_t now = time(NULL);
        char filename[512];
        snprintf(filename, sizeof(filename), "%s/stats_%ld.csv", output_dir, now);
        
        FILE *f = fopen(filename, "w");
        if (!f) {
            fprintf(stderr, "Failed to open output file: %s\n", strerror(errno));
            sleep(interval);
            continue;
        }
        
        // Write header
        fprintf(f, "timestamp,pid,total_boost_time,is_boosted\n");
        
        // Collect stats for each PID
        for (int i = 0; i < MAX_PIDS; i++) {
            int pid = i;
            u_int64_t boost_until = 0;
            u_int64_t total_boost = 0;
            
            if (bpf_map_lookup_elem(boost_until_fd, &pid, &boost_until) == 0) {
                int is_boosted = (boost_until > now * 1000000) ? 1 : 0;
                
                // Get total boost time
                bpf_map_lookup_elem(total_boost_time_fd, &pid, &total_boost);
                
                // Write record
                fprintf(f, "%ld,%d,%lu,%d\n", now, pid, total_boost, is_boosted);
            }
        }
        
        fclose(f);
        sleep(interval);
    }
    
    return 0;
}