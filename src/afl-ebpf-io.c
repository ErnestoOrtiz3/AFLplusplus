// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 AFL++ team */
#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <string.h>
#include <linux/types.h>

/* Define trace event structures if not available */
#ifndef TRACE_EVENT_RAW_SYS_ENTER_DEFINED
struct trace_event_raw_sys_enter {
  unsigned long long unused;
  long syscall_nr;
  unsigned long args[6];
};
#define TRACE_EVENT_RAW_SYS_ENTER_DEFINED
#endif

#ifndef TRACE_EVENT_RAW_SYS_EXIT_DEFINED
struct trace_event_raw_sys_exit {
  unsigned long long unused;
  long syscall_nr;
  long ret;
};
#define TRACE_EVENT_RAW_SYS_EXIT_DEFINED
#endif

/* Define size_t for eBPF context */
#ifndef size_t
typedef __kernel_size_t size_t;
#endif

#ifndef ssize_t
typedef __kernel_ssize_t ssize_t;
#endif

/* Maximum path length for file operations */
#define MAX_PATH_LEN 256

/* Maximum file size that can be intercepted */
#define MAX_FILE_SIZE (1 << 20)  // 1MB

/* Structure to hold file data */
struct file_data {
  char     path[MAX_PATH_LEN];  // File path
  __u32    size;                // File size
  __u32    offset;              // Offset in shared memory
  __u8     in_use;              // Whether this entry is in use
};

/* Configuration structure */
struct config {
  __u8     enabled;             // Whether file interception is enabled
  __u32    shm_size;            // Size of shared memory region
};

/* Maps */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, char[MAX_PATH_LEN]);
  __type(value, struct file_data);
} files SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct config);
} config SEC(".maps");

/* Map to track file descriptors of intercepted files */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, int);  /* file descriptor */
  __type(value, struct file_data);
} fd_to_data SEC(".maps");

/* Temporary storage for file path during syscall processing */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);  /* thread ID */
  __type(value, struct file_data);
} temp_files SEC(".maps");

/* Temporary storage for read operations */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);  /* thread ID */
  __type(value, struct {
    void *buf;
    size_t count;
    struct file_data *data;
  });
} temp_reads SEC(".maps");

/* Map to store shared memory information */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct {
    __u64 addr;     /* User space address of shared memory */
    __u32 size;     /* Size of shared memory region */
  });
} shm_info SEC(".maps");

/* Map for temporary filename storage */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, char[MAX_PATH_LEN]);
} filename_map SEC(".maps");

/* Helper function to check if a file should be intercepted */
static inline int should_intercept(const char *filename, struct file_data *data) {
  /* Check if interception is enabled */
  __u32 key = 0;
  struct config *cfg = bpf_map_lookup_elem(&config, &key);
  if (!cfg || !cfg->enabled)
    return 0;
  
  /* Look up the file in our map */
  struct file_data *found = bpf_map_lookup_elem(&files, filename);
  if (found) {
    /* Copy the data to the output parameter if provided */
    if (data) {
      data->size = found->size;
      data->offset = found->offset;
      data->in_use = found->in_use;
      /* Copy path in small chunks to avoid stack usage */
      for (int i = 0; i < MAX_PATH_LEN; i += 8) {
        __builtin_memcpy(&data->path[i], &found->path[i], 
                         (i + 8 <= MAX_PATH_LEN) ? 8 : (MAX_PATH_LEN - i));
      }
    }
    return 1;
  }
  return 0;
}

/* Attach to open syscall */
SEC("tracepoint/syscalls/sys_enter_open")
int trace_open_enter(struct trace_event_raw_sys_enter *ctx) {
  __u32 key = 0;
  char *filename = bpf_map_lookup_elem(&filename_map, &key);
  if (!filename)
    return 0;
  
  /* Get filename from syscall arguments */
  bpf_probe_read_user_str(filename, MAX_PATH_LEN, (const char *)ctx->args[0]);
  
  /* Check if we should intercept this file */
  if (should_intercept(filename, NULL)) {
    /* We'll handle this in the return probe */
    bpf_printk("Intercepting open for file: %s\n", filename);
  }
  
  return 0;
}

/* Attach to openat syscall (more commonly used than open) */
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat_enter(struct trace_event_raw_sys_enter *ctx) {
  __u32 key = 0;
  char *filename = bpf_map_lookup_elem(&filename_map, &key);
  if (!filename)
    return 0;
  
  /* Get filename from syscall arguments */
  bpf_probe_read_user_str(filename, MAX_PATH_LEN, (const char *)ctx->args[1]);
  
  struct file_data data = {0};
  
  /* Check if we should intercept this file */
  if (should_intercept(filename, &data)) {
    /* Store file data for the exit handler */
    __u32 tid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&temp_files, &tid, &data, BPF_ANY);
    
    bpf_printk("Intercepting openat for file: %s\n", filename);
  }
  
  return 0;
}

/* Attach to openat syscall return */
SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(void *ctx) {
  int fd = ((struct trace_event_raw_sys_exit *)ctx)->ret;
  
  /* Only process successful opens */
  if (fd < 0)
    return 0;
  
  /* Get thread ID to look up file data */
  __u32 tid = bpf_get_current_pid_tgid();
  
  /* Check if this is a file we want to intercept */
  struct file_data *data = bpf_map_lookup_elem(&temp_files, &tid);
  if (data) {
    /* Store the mapping from fd to file data */
    bpf_map_update_elem(&fd_to_data, &fd, data, BPF_ANY);
    
    /* Clean up temporary storage */
    bpf_map_delete_elem(&temp_files, &tid);
    
    bpf_printk("Intercepted fd %d for file\n", fd);
  }
  
  return 0;
}

/* Attach to read syscall */
SEC("tracepoint/syscalls/sys_enter_read")
int trace_read_enter(struct trace_event_raw_sys_enter *ctx) {
  int fd = ctx->args[0];
  void *buf = (void *)ctx->args[1];
  size_t count = (size_t)ctx->args[2];
  
  /* Check if this is a file descriptor we're intercepting */
  struct file_data *data = bpf_map_lookup_elem(&fd_to_data, &fd);
  if (!data) {
    return 0;  /* Not an intercepted file */
  }
  
  /* Store information for the exit handler */
  struct {
    void *buf;
    size_t count;
    struct file_data *data;
  } read_info;
  
  read_info.buf = buf;
  read_info.count = count;
  read_info.data = data;
  
  __u32 tid = bpf_get_current_pid_tgid();
  bpf_map_update_elem(&temp_reads, &tid, &read_info, BPF_ANY);
  
  bpf_printk("Intercepting read on fd %d\n", fd);
  
  return 0;
}

/* Attach to read syscall return */
SEC("tracepoint/syscalls/sys_exit_read")
int trace_read_exit(void *ctx) {
  ssize_t ret = ((struct trace_event_raw_sys_exit *)ctx)->ret;
  
  /* Only process successful reads */
  if (ret <= 0)
    return 0;
  
  /* Get thread ID to look up read info */
  __u32 tid = bpf_get_current_pid_tgid();
  
  /* Check if this is a read we want to intercept */
  struct {
    void *buf;
    size_t count;
    struct file_data *data;
  } *read_info = bpf_map_lookup_elem(&temp_reads, &tid);
  
  if (read_info) {
    /* Get configuration */
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&config, &key);
    if (!cfg) {
      goto cleanup;
    }
    
    /* Get shared memory info */
    struct {
      __u64 addr;
      __u32 size;
    } *shm = bpf_map_lookup_elem(&shm_info, &key);
    
    if (!shm || !shm->addr) {
      bpf_printk("Shared memory not configured\n");
      goto cleanup;
    }
    
    /* Calculate how much data to copy */
    size_t to_copy = read_info->data->size;
    if (to_copy > ret) to_copy = ret;
    if (to_copy > read_info->count) to_copy = read_info->count;
    
    /* Calculate source address in shared memory */
    __u64 src_addr = shm->addr + read_info->data->offset;
    
    /* We need to copy in chunks due to BPF verifier limitations */
    #define CHUNK_SIZE 64
    char buffer[CHUNK_SIZE];
    
    for (size_t i = 0; i < to_copy; i += CHUNK_SIZE) {
      size_t chunk = (to_copy - i < CHUNK_SIZE) ? (to_copy - i) : CHUNK_SIZE;
      
      /* Read from shared memory */
      if (bpf_probe_read(buffer, chunk, (void *)(src_addr + i)) != 0) {
        bpf_printk("Failed to read from shared memory at offset %zu\n", i);
        break;
      }
      
      /* Write to user buffer */
      if (bpf_probe_write_user(read_info->buf + i, buffer, chunk) != 0) {
        bpf_printk("Failed to write to user buffer at offset %zu\n", i);
        break;
      }
    }
    
    bpf_printk("Intercepted read: copied %zu bytes from shared memory\n", to_copy);
    
  cleanup:
    /* Clean up temporary storage */
    bpf_map_delete_elem(&temp_reads, &tid);
  }
  
  return 0;
}

/* License must be GPL for tracepoints */
char LICENSE[] SEC("license") = "GPL";
