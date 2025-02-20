#include "afl-ebpf.h"
#include "debug.h"
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#ifdef HAVE_EBPF
#include <linux/bpf.h>
#include <linux/version.h>
#include <sys/syscall.h>
#include <sys/utsname.h>

// Minimum kernel version required for our eBPF programs
#define MIN_KERNEL_VERSION 4
#define MIN_KERNEL_PATCHLEVEL 15

static int check_kernel_version(void) {
    struct utsname utsname;
    if (uname(&utsname) < 0) {
        WARNF("uname() failed: %s", strerror(errno));
        return 0;
    }

    int major, minor;
    if (sscanf(utsname.release, "%d.%d", &major, &minor) != 2) {
        WARNF("Failed to parse kernel version: %s", utsname.release);
        return 0;
    }

    if (major < MIN_KERNEL_VERSION || 
        (major == MIN_KERNEL_VERSION && minor < MIN_KERNEL_PATCHLEVEL)) {
        WARNF("Kernel version %d.%d too old, need >= %d.%d", 
              major, minor, MIN_KERNEL_VERSION, MIN_KERNEL_PATCHLEVEL);
        return 0;
    }

    return 1;
}

static int check_bpf_syscall_access(void) {
    int ret = syscall(__NR_bpf, BPF_MAP_CREATE, NULL, 0);
    if (ret >= 0) {
        close(ret); // Clean up if syscall succeeded
        return 1;
    }
    
    if (errno == EPERM) {
        WARNF("No permission to use BPF syscall. Try running with sudo or setting CAP_BPF capability");
        return 0;
    }
    
    return 0;
}

static int check_bpf_filesystem(void) {
    // Check if BPF filesystem is mounted
    if (access("/sys/fs/bpf", R_OK | W_OK) != 0) {
        WARNF("No access to /sys/fs/bpf filesystem: %s", strerror(errno));
        return 0;
    }
    return 1;
}

static int check_perf_events(void) {
    int fd = open("/proc/sys/kernel/perf_event_paranoid", O_RDONLY);
    if (fd < 0) {
        WARNF("Cannot check perf_event_paranoid: %s", strerror(errno));
        return 0;
    }

    char buf[16] = {0};
    if (read(fd, buf, sizeof(buf) - 1) < 0) {
        close(fd);
        return 0;
    }
    close(fd);

    int paranoid_level = atoi(buf);
    if (paranoid_level > 1) {
        WARNF("perf_event_paranoid level too restrictive: %d", paranoid_level);
        return 0;
    }

    return 1;
}

int check_ebpf_available(void) {
    if (!check_kernel_version()) {
        SAYF(cYEL "[!] " cRST 
             "Kernel version too old for eBPF support. Falling back to traditional stats.\n");
        return 0;
    }

    if (!check_bpf_syscall_access()) {
        SAYF(cYEL "[!] " cRST 
             "No BPF syscall permission. Run with sudo or set capabilities:\n"
             "    sudo setcap cap_bpf+ep %s\n"
             "Falling back to traditional stats.\n", getenv("_"));
        return 0;
    }

    if (!check_bpf_filesystem()) {
        SAYF(cYEL "[!] " cRST 
             "No access to BPF filesystem. Mount it with:\n"
             "    sudo mount -t bpf bpf /sys/fs/bpf/\n"
             "Falling back to traditional stats.\n");
        return 0;
    }

    if (!check_perf_events()) {
        SAYF(cYEL "[!] " cRST 
             "Restricted perf_event access. Adjust with:\n"
             "    sudo sysctl kernel.perf_event_paranoid=1\n"
             "Falling back to traditional stats.\n");
        return 0;
    }

    return 1;
}

#endif /* HAVE_EBPF */