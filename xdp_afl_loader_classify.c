// Enhanced XDP loader for AFL network fuzzing with classification
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

static int ifindex;
static struct bpf_object *obj;
static struct bpf_link *xdp_link = NULL;
static volatile int running = 1;

void int_handler(int sig)
{
    running = 0;
}

// Function to print statistics from the stats map
void print_stats(int map_fd)
{
    __u32 key;
    __u64 value;
    
    printf("\n--- XDP Packet Statistics ---\n");
    
    // Print total packets
    key = 0; // STAT_TOTAL
    if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
        printf("Total packets: %llu\n", value);
    }
    
    // Print AFL packets
    key = 1; // STAT_AFL
    if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
        printf("AFL packets:   %llu\n", value);
    }
    
    // Print non-AFL packets
    key = 2; // STAT_NON_AFL
    if (bpf_map_lookup_elem(map_fd, &key, &value) == 0) {
        printf("Other packets: %llu\n", value);
    }
    
    printf("----------------------------\n");
}

int main(int argc, char **argv)
{
    int prog_fd, ports_map_fd, stats_map_fd, err;
    char filename[256];
    struct bpf_program *prog;
    int no_btf = 0;
    int port_arg_start = 3;
    
    if (argc < 3) {
        printf("Usage: %s <ifname> <xdp-object> [--no-btf] [afl_port1 afl_port2 ...]\n", argv[0]);
        return 1;
    }
    
    // Get interface index
    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        printf("Interface %s not found\n", argv[1]);
        return 1;
    }
    
    // Check for --no-btf option
    if (argc > 3 && strcmp(argv[3], "--no-btf") == 0) {
        no_btf = 1;
        port_arg_start = 4;
        printf("BTF support disabled by command line option\n");
    }
    
    // Open BPF object file
    snprintf(filename, sizeof(filename), "%s", argv[2]);
    
    if (no_btf) {
        // Use relaxed maps option to load without BTF
        struct bpf_object_open_opts opts = {
            .sz = sizeof(struct bpf_object_open_opts),
            .relaxed_maps = true,
        };
        obj = bpf_object__open_file(filename, &opts);
    } else {
        // Try normal loading first
        obj = bpf_object__open_file(filename, NULL);
        if (libbpf_get_error(obj)) {
            printf("Warning: Failed to open with BTF, trying fallback method...\n");
            struct bpf_object_open_opts opts = {
                .sz = sizeof(struct bpf_object_open_opts),
                .relaxed_maps = true,
            };
            obj = bpf_object__open_file(filename, &opts);
        }
    }
    
    if (libbpf_get_error(obj)) {
        printf("Error opening BPF object file: %s\n", strerror(-libbpf_get_error(obj)));
        return 1;
    }
    
    // Load BPF program
    err = bpf_object__load(obj);
    if (err) {
        printf("Error loading BPF object file: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    
    // Find XDP program
    prog = bpf_object__find_program_by_name(obj, "xdp_afl_classifier");
    if (!prog) {
        // Try alternative name if the first one fails
        prog = bpf_object__find_program_by_name(obj, "xdp_afl_classify");
        if (!prog) {
            printf("Error finding XDP program\n");
            bpf_object__close(obj);
            return 1;
        }
    }
    
    // Get program FD
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        printf("Error getting program FD\n");
        bpf_object__close(obj);
        return 1;
    }
    
    // Get map FDs
    ports_map_fd = bpf_object__find_map_fd_by_name(obj, "afl_ports");
    if (ports_map_fd < 0) {
        // Try legacy map name
        ports_map_fd = bpf_object__find_map_fd_by_name(obj, "afl_ports_legacy");
        if (ports_map_fd < 0) {
            printf("Error finding AFL ports map\n");
            bpf_object__close(obj);
            return 1;
        }
    }
    
    stats_map_fd = bpf_object__find_map_fd_by_name(obj, "stats");
    if (stats_map_fd < 0) {
        // Try legacy map name
        stats_map_fd = bpf_object__find_map_fd_by_name(obj, "stats_legacy");
        if (stats_map_fd < 0) {
            printf("Error finding stats map\n");
            bpf_object__close(obj);
            return 1;
        }
    }
    
    // Add AFL ports to the map
    for (int i = port_arg_start; i < argc; i++) {
        __u16 port = atoi(argv[i]);
        __u8 value = 1;
        
        if (port > 0) {
            err = bpf_map_update_elem(ports_map_fd, &port, &value, BPF_ANY);
            if (err) {
                printf("Error adding port %d to map: %s\n", port, strerror(-err));
            } else {
                printf("Added AFL port: %d\n", port);
            }
        }
    }
    
    // Attach XDP program using the newer API
    xdp_link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(xdp_link)) {
        err = -libbpf_get_error(xdp_link);
        printf("Error attaching XDP program: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    
    printf("XDP program successfully attached to interface %s\n", argv[1]);
    printf("Press Ctrl+C to detach and exit\n");
    
    // Set up signal handler
    signal(SIGINT, int_handler);
    
    // Print stats periodically
    while (running) {
        sleep(1);
        print_stats(stats_map_fd);
    }
    
    // Detach XDP program
    bpf_link__destroy(xdp_link);
    bpf_object__close(obj);
    
    printf("XDP program detached\n");
    return 0;
}
