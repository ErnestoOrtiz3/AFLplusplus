// Simple XDP loader for AFL network fuzzing
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>  // For sleep function
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <net/if.h>
#include <linux/if_link.h>

int main(int argc, char **argv)
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    int prog_fd, err;
    char filename[256];
    int ifindex;
    
    if (argc != 3) {
        printf("Usage: %s <ifname> <xdp-object>\n", argv[0]);
        return 1;
    }
    
    ifindex = if_nametoindex(argv[1]);
    if (!ifindex) {
        printf("Interface %s not found\n", argv[1]);
        return 1;
    }
    
    snprintf(filename, sizeof(filename), "%s", argv[2]);
    
    obj = bpf_object__open_file(filename, NULL);
    if (libbpf_get_error(obj)) {
        printf("Error opening BPF object file\n");
        return 1;
    }
    
    err = bpf_object__load(obj);
    if (err) {
        printf("Error loading BPF object file: %s\n", strerror(-err));
        bpf_object__close(obj);
        return 1;
    }
    
    prog = bpf_object__find_program_by_name(obj, "xdp_afl_pass");
    if (!prog) {
        printf("Error finding XDP program\n");
        bpf_object__close(obj);
        return 1;
    }
    
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        printf("Error getting program FD\n");
        bpf_object__close(obj);
        return 1;
    }
    
    // Use the newer API to attach XDP program
    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        printf("Error attaching XDP program: %s\n", strerror(errno));
        bpf_object__close(obj);
        return 1;
    }
    
    printf("XDP program successfully attached to interface %s\n", argv[1]);
    printf("Press Ctrl+C to detach and exit\n");
    
    // Wait for Ctrl+C
    while (1) {
        sleep(1);
    }
    
    // Cleanup (this code is never reached in the current implementation)
    bpf_link__destroy(link);
    bpf_object__close(obj);
    
    return 0;
}
