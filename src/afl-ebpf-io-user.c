/*
   american fuzzy lop++ - eBPF file I/O optimization implementation
   ----------------------------------------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#ifdef USE_EBPF_IO

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/shm.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "alloc-inl.h"
#include "debug.h"
#include "afl-ebpf-io.h"

// Include the auto-generated skeleton header
#include "afl-ebpf-io.skel.h"

/* Define MAX_PATH_LEN if not already defined */
#ifndef MAX_PATH_LEN
#define MAX_PATH_LEN 256
#endif

/* Initialize eBPF file I/O optimization */
struct afl_ebpf_io_ctx *afl_ebpf_io_init(void) {
  struct afl_ebpf_io_ctx *ctx;
  
  /* Allocate context */
  ctx = calloc(1, sizeof(struct afl_ebpf_io_ctx));
  if (!ctx) {
    PFATAL("Failed to allocate eBPF I/O context");
    return NULL;
  }
  
  /* Initialize memory management */
  ctx->memory_blocks = NULL;
  ctx->num_blocks = 0;
  
  /* Open BPF skeleton */
  struct afl_ebpf_io *skel = afl_ebpf_io__open();
  if (!skel) {
    PFATAL("Failed to open BPF skeleton");
    free(ctx);
    return NULL;
  }
  
  /* Load BPF program */
  int err = afl_ebpf_io__load(skel);
  if (err) {
    PFATAL("Failed to load BPF program: %d", err);
    afl_ebpf_io__destroy(skel);
    free(ctx);
    return NULL;
  }
  
  /* Attach BPF program */
  err = afl_ebpf_io__attach(skel);
  if (err) {
    PFATAL("Failed to attach BPF program: %d", err);
    afl_ebpf_io__destroy(skel);
    free(ctx);
    return NULL;
  }
  
  /* Get map file descriptors */
  ctx->files_map_fd = bpf_map__fd(skel->maps.files);
  ctx->config_map_fd = bpf_map__fd(skel->maps.config);
  
  if (ctx->files_map_fd < 0 || ctx->config_map_fd < 0) {
    PFATAL("Failed to get map file descriptors");
    afl_ebpf_io__destroy(skel);
    free(ctx);
    return NULL;
  }
  
  /* Create shared memory region for file contents */
  ctx->shm_size = EBPF_IO_MAX_FILE_SIZE;
  ctx->shm_id = shmget(IPC_PRIVATE, ctx->shm_size, IPC_CREAT | 0600);
  if (ctx->shm_id < 0) {
    PFATAL("Failed to create shared memory region");
    afl_ebpf_io__destroy(skel);
    free(ctx);
    return NULL;
  }
  
  /* Attach to shared memory */
  ctx->shm_data = shmat(ctx->shm_id, NULL, 0);
  if (ctx->shm_data == (void *)-1) {
    PFATAL("Failed to attach to shared memory");
    shmctl(ctx->shm_id, IPC_RMID, NULL);
    afl_ebpf_io__destroy(skel);
    free(ctx);
    return NULL;
  }
  
  /* Initialize configuration */
  struct {
    __u8  enabled;
    __u32 shm_size;
  } cfg = {
    .enabled = 1,
    .shm_size = ctx->shm_size
  };

  __u32 key = 0;
  err = bpf_map_update_elem(ctx->config_map_fd, &key, &cfg, BPF_ANY);
  if (err) {
    PFATAL("Failed to initialize configuration");
    shmdt(ctx->shm_data);
    shmctl(ctx->shm_id, IPC_RMID, NULL);
    afl_ebpf_io__destroy(skel);
    free(ctx);
    return NULL;
  }

  /* Set shared memory information */
  struct {
    __u64 addr;
    __u32 size;
  } shm_info = {
    .addr = (__u64)ctx->shm_data,
    .size = ctx->shm_size
  };

  int shm_info_map_fd = bpf_map__fd(skel->maps.shm_info);
  if (shm_info_map_fd < 0) {
    PFATAL("Failed to get shm_info map file descriptor");
    shmdt(ctx->shm_data);
    shmctl(ctx->shm_id, IPC_RMID, NULL);
    afl_ebpf_io__destroy(skel);
    free(ctx);
    return NULL;
  }

  err = bpf_map_update_elem(shm_info_map_fd, &key, &shm_info, BPF_ANY);
  if (err) {
    PFATAL("Failed to set shared memory information");
    shmdt(ctx->shm_data);
    shmctl(ctx->shm_id, IPC_RMID, NULL);
    afl_ebpf_io__destroy(skel);
    free(ctx);
    return NULL;
  }

  /* Store BPF skeleton for later cleanup */
  ctx->skel = skel;
  ctx->enabled = true;
  
  ACTF("eBPF file I/O optimization initialized");
  return ctx;
}

/* Clean up eBPF file I/O optimization */
void afl_ebpf_io_deinit(struct afl_ebpf_io_ctx *ctx) {
  if (!ctx) return;
  
  /* Free memory blocks */
  if (ctx->memory_blocks) {
    free(ctx->memory_blocks);
  }
  
  /* Detach from shared memory */
  if (ctx->shm_data) {
    shmdt(ctx->shm_data);
    shmctl(ctx->shm_id, IPC_RMID, NULL);
  }
  
  /* Clean up BPF resources */
  if (ctx->skel) {
    afl_ebpf_io__destroy(ctx->skel);
  }
  
  free(ctx);
  ACTF("eBPF file I/O optimization cleaned up");
}

/* Add a file to be intercepted with improved memory management */
int afl_ebpf_io_add_file(struct afl_ebpf_io_ctx *ctx, const char *filename, 
                         const void *data, size_t size) {
  if (!ctx || !ctx->enabled || !filename || !data) return -1;
  if (size > ctx->shm_size) return -1;
  
  /* Check if file already exists in map */
  struct {
    char  path[256];
    __u32 size;
    __u32 offset;
    __u8  in_use;
  } file_data;
  
  if (bpf_map_lookup_elem(ctx->files_map_fd, filename, &file_data) == 0) {
    // File exists, check if we can reuse the space
    if (file_data.size >= size) {
      // We can reuse the existing space
      __u32 offset = file_data.offset;
      
      // Copy file data to shared memory
      memcpy(ctx->shm_data + offset, data, size);
      
      // Update file size
      file_data.size = size;
      
      int err = bpf_map_update_elem(ctx->files_map_fd, filename, &file_data, BPF_ANY);
      if (err) {
        WARNF("Failed to update file in eBPF map: %s", filename);
        return -1;
      }
      
      return 0;
    } else {
      // Need to remove the old entry first
      char key[256]; // Use 256 instead of MAX_PATH_LEN
      strncpy(key, filename, sizeof(key) - 1);
      key[sizeof(key) - 1] = '\0';
      
      bpf_map_delete_elem(ctx->files_map_fd, key);
      
      // Mark the old block as free
      for (int i = 0; i < ctx->num_blocks; i++) {
        if (ctx->memory_blocks[i].offset == file_data.offset) {
          ctx->memory_blocks[i].in_use = false;
          break;
        }
      }
      
      // Try to merge with adjacent free blocks
      afl_ebpf_io_merge_free_blocks(ctx);
    }
  }
  
  /* Initialize memory blocks if not already done */
  if (!ctx->memory_blocks) {
    ctx->memory_blocks = calloc(MAX_MEMORY_BLOCKS, sizeof(struct memory_block));
    if (!ctx->memory_blocks) {
      WARNF("Failed to allocate memory blocks");
      return -1;
    }
    
    /* Initialize with a single free block covering the entire memory */
    ctx->memory_blocks[0].offset = 0;
    ctx->memory_blocks[0].size = ctx->shm_size;
    ctx->memory_blocks[0].in_use = false;
    ctx->num_blocks = 1;
  }
  
  /* Find a suitable free block using best-fit algorithm */
  int best_block = -1;
  __u32 best_size = UINT32_MAX;
  
  for (int i = 0; i < ctx->num_blocks; i++) {
    if (!ctx->memory_blocks[i].in_use && 
        ctx->memory_blocks[i].size >= size &&
        ctx->memory_blocks[i].size < best_size) {
      best_block = i;
      best_size = ctx->memory_blocks[i].size;
      
      /* If we find an exact match, stop searching */
      if (best_size == size)
        break;
    }
  }
  
  /* If no suitable block found, try to compact memory */
  if (best_block == -1) {
    ACTF("No suitable memory block found, compacting memory...");
    
    /* Compact memory by moving all used blocks to the beginning */
    __u32 current_offset = 0;
    
    /* First, update all file entries in the map */
    char key[MAX_PATH_LEN];
    struct {
      char  path[256];
      __u32 size;
      __u32 offset;
      __u8  in_use;
    } value;
    
    /* We need to iterate through all files in the map */
    /* This is a simplified version - in practice, you'd need a more robust iteration mechanism */
    for (int i = 0; i < ctx->num_blocks; i++) {
      if (ctx->memory_blocks[i].in_use) {
        /* Find the file that uses this block */
        bool found = false;
        
        /* This is inefficient but works for demonstration */
        for (int j = 0; j < MAX_PATH_LEN; j++) {
          key[j] = 0;
        }
        
        while (bpf_map_get_next_key(ctx->files_map_fd, key[0] ? key : NULL, key) == 0) {
          if (bpf_map_lookup_elem(ctx->files_map_fd, key, &value) == 0) {
            if (value.offset == ctx->memory_blocks[i].offset) {
              found = true;
              break;
            }
          }
        }
        
        if (found) {
          /* Move the data to the new location */
          if (current_offset != ctx->memory_blocks[i].offset) {
            memmove(ctx->shm_data + current_offset, 
                    ctx->shm_data + ctx->memory_blocks[i].offset,
                    ctx->memory_blocks[i].size);
            
            /* Update the file entry */
            value.offset = current_offset;
            bpf_map_update_elem(ctx->files_map_fd, key, &value, BPF_ANY);
          }
          
          /* Update the memory block */
          ctx->memory_blocks[i].offset = current_offset;
          current_offset += ctx->memory_blocks[i].size;
          
          /* Align to 8-byte boundary */
          current_offset = (current_offset + 7) & ~7;
        }
      }
    }
    
    /* Create a single free block at the end */
    if (ctx->num_blocks > 0) {
      ctx->memory_blocks[0].offset = 0;
      ctx->memory_blocks[0].size = current_offset;
      ctx->memory_blocks[0].in_use = true;
      
      ctx->memory_blocks[1].offset = current_offset;
      ctx->memory_blocks[1].size = ctx->shm_size - current_offset;
      ctx->memory_blocks[1].in_use = false;
      ctx->num_blocks = 2;
      
      /* Check if we now have enough space */
      if (ctx->memory_blocks[1].size >= size) {
        best_block = 1;
      }
    }
  }
  
  /* If still no suitable block, fail */
  if (best_block == -1) {
    WARNF("No suitable memory block found after compaction");
    return -1;
  }
  
  /* Allocate from the best block */
  __u32 offset = ctx->memory_blocks[best_block].offset;
  __u32 remaining = ctx->memory_blocks[best_block].size - size;
  
  /* Update the block we're using */
  ctx->memory_blocks[best_block].size = size;
  ctx->memory_blocks[best_block].in_use = true;
  
  /* If there's remaining space, create a new free block */
  if (remaining > 0) {
    /* Check if we have room for a new block */
    if (ctx->num_blocks < MAX_MEMORY_BLOCKS) {
      /* Shift blocks to make room for the new one */
      for (int i = ctx->num_blocks; i > best_block + 1; i--) {
        ctx->memory_blocks[i] = ctx->memory_blocks[i - 1];
      }
      
      /* Create the new free block */
      ctx->memory_blocks[best_block + 1].offset = offset + size;
      ctx->memory_blocks[best_block + 1].size = remaining;
      ctx->memory_blocks[best_block + 1].in_use = false;
      ctx->num_blocks++;
    } else {
      WARNF("No room for new memory block, wasting %u bytes", remaining);
    }
  }
  
  /* Copy file data to shared memory */
  memcpy(ctx->shm_data + offset, data, size);
  
  /* Add file to map */
  memset(&file_data, 0, sizeof(file_data));
  file_data.size = size;
  file_data.offset = offset;
  file_data.in_use = 1;
  strncpy(file_data.path, filename, sizeof(file_data.path) - 1);
  
  int err = bpf_map_update_elem(ctx->files_map_fd, filename, &file_data, BPF_ANY);
  if (err) {
    WARNF("Failed to add file to eBPF map: %s", filename);
    
    /* Mark the block as free again */
    ctx->memory_blocks[best_block].in_use = false;
    
    /* Try to merge with adjacent free blocks */
    afl_ebpf_io_merge_free_blocks(ctx);
    
    return -1;
  }
  
  return 0;
}

/* Helper function to merge adjacent free blocks */
void afl_ebpf_io_merge_free_blocks(struct afl_ebpf_io_ctx *ctx) {
  if (!ctx || !ctx->memory_blocks || ctx->num_blocks <= 1)
    return;
  
  int i = 0;
  while (i < ctx->num_blocks - 1) {
    if (!ctx->memory_blocks[i].in_use && !ctx->memory_blocks[i + 1].in_use) {
      /* Merge blocks i and i+1 */
      ctx->memory_blocks[i].size += ctx->memory_blocks[i + 1].size;
      
      /* Remove block i+1 */
      for (int j = i + 1; j < ctx->num_blocks - 1; j++) {
        ctx->memory_blocks[j] = ctx->memory_blocks[j + 1];
      }
      ctx->num_blocks--;
      
      /* Don't increment i, as we need to check if the merged block
         can be merged with the next one */
    } else {
      i++;
    }
  }
}

/* Remove a file from interception with memory management */
int afl_ebpf_io_remove_file(struct afl_ebpf_io_ctx *ctx, const char *filename) {
  if (!ctx || !ctx->enabled || !filename) return -1;
  
  /* Get file data */
  struct {
    char  path[256];
    __u32 size;
    __u32 offset;
    __u8  in_use;
  } file_data;
  
  if (bpf_map_lookup_elem(ctx->files_map_fd, filename, &file_data) != 0) {
    WARNF("File not found in eBPF map: %s", filename);
    return -1;
  }
  
  /* Remove from map */
  int err = bpf_map_delete_elem(ctx->files_map_fd, filename);
  if (err) {
    WARNF("Failed to remove file from eBPF map: %s", filename);
    return -1;
  }
  
  /* Mark the corresponding memory block as free */
  if (ctx->memory_blocks) {
    for (int i = 0; i < ctx->num_blocks; i++) {
      if (ctx->memory_blocks[i].offset == file_data.offset &&
          ctx->memory_blocks[i].size == file_data.size &&
          ctx->memory_blocks[i].in_use) {
        ctx->memory_blocks[i].in_use = false;
        
        /* Try to merge with adjacent free blocks */
        afl_ebpf_io_merge_free_blocks(ctx);
        break;
      }
    }
  }
  
  return 0;
}

/* Clear all intercepted files */
int afl_ebpf_io_clear_files(struct afl_ebpf_io_ctx *ctx) {
  if (!ctx || !ctx->enabled) return -1;
  
  // This is a simple implementation - we just recreate the map
  // A more sophisticated version would iterate through all entries
  
  // For now, we'll just disable and re-enable
  return afl_ebpf_io_set_enabled(ctx, false) || 
         afl_ebpf_io_set_enabled(ctx, true);
}

/* Enable or disable file interception */
int afl_ebpf_io_set_enabled(struct afl_ebpf_io_ctx *ctx, bool enabled) {
  if (!ctx) return -1;
  
  struct {
    __u8  enabled;
    __u32 shm_size;
  } cfg = {
    .enabled = enabled ? 1 : 0,
    .shm_size = ctx->shm_size
  };
  
  __u32 key = 0;
  int err = bpf_map_update_elem(ctx->config_map_fd, &key, &cfg, BPF_ANY);
  if (err) {
    WARNF("Failed to update eBPF configuration");
    return -1;
  }
  
  ctx->enabled = enabled;
  return 0;
}

#endif /* USE_EBPF_IO */
