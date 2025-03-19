/*
   american fuzzy lop++ - eBPF file I/O optimization header
   ---------------------------------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _AFL_EBPF_IO_H
#define _AFL_EBPF_IO_H

#ifdef USE_EBPF_IO

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <sys/types.h>

// Forward declaration for skeleton structure
struct afl_ebpf_io_skel;

/* Maximum size of shared memory for file contents */
#define EBPF_IO_MAX_FILE_SIZE (1 << 20)  // 1MB default

/* Maximum number of memory blocks to track */
#define MAX_MEMORY_BLOCKS 128

/* Structure to track memory allocation in shared memory */
struct memory_block {
  __u32 offset;
  __u32 size;
  bool in_use;
};

/* Context for eBPF file I/O optimization */
struct afl_ebpf_io_ctx {
  struct afl_ebpf_io_skel *skel;  /* BPF skeleton */
  int files_map_fd;               /* File descriptor for files map */
  int config_map_fd;              /* File descriptor for config map */
  int shm_id;                     /* Shared memory ID */
  void *shm_data;                 /* Pointer to shared memory */
  size_t shm_size;                /* Size of shared memory */
  bool enabled;                   /* Whether file interception is enabled */
  
  /* Memory management */
  struct memory_block *memory_blocks;  /* Array of memory blocks */
  int num_blocks;                      /* Number of memory blocks in use */
};

/* Function declarations */
/* Initialize eBPF file I/O optimization */
struct afl_ebpf_io_ctx *afl_ebpf_io_init(void);

/* Clean up eBPF file I/O optimization */
void afl_ebpf_io_deinit(struct afl_ebpf_io_ctx *ctx);

/* Add a file to be intercepted */
int afl_ebpf_io_add_file(struct afl_ebpf_io_ctx *ctx, const char *filename, 
                         const void *data, size_t size);

/* Remove a file from interception */
int afl_ebpf_io_remove_file(struct afl_ebpf_io_ctx *ctx, const char *filename);

/* Clear all intercepted files */
int afl_ebpf_io_clear_files(struct afl_ebpf_io_ctx *ctx);

/* Enable or disable file interception */
int afl_ebpf_io_set_enabled(struct afl_ebpf_io_ctx *ctx, bool enabled);

/* Function to merge adjacent free blocks */
void afl_ebpf_io_merge_free_blocks(struct afl_ebpf_io_ctx *ctx);

#endif /* USE_EBPF_IO */

#endif /* !_AFL_EBPF_IO_H */
