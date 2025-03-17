/*
   american fuzzy lop++ - eBPF support
   ----------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#ifdef USE_EBPF

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "alloc-inl.h"
#include "debug.h"
#include "afl-ebpf.h"

// Include the auto-generated skeleton headers
#include "afl-ebpf-perf.skel.h"
#include "afl-ebpf-execve.skel.h"

// Helper function to create perf event
static long perf_event_open(struct perf_event_attr *hw_event, pid_t pid,
                           int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, hw_event, pid, cpu, group_fd, flags);
}

/* Initialize eBPF context */
struct afl_ebpf_ctx *afl_ebpf_init(const char *target_path) {
  struct afl_ebpf_ctx *ctx = calloc(1, sizeof(struct afl_ebpf_ctx));
  if (!ctx) {
    PFATAL("Failed to allocate eBPF context");
    return NULL;
  }

  // Initialize context
  ctx->enabled = false;
  ctx->prog_fd = -1;
  ctx->map_fd = -1;
  ctx->perf_fd = -1;
  ctx->mode = getenv("AFL_EBPF_MODE") ? atoi(getenv("AFL_EBPF_MODE")) : EBPF_MODE_PERF;

  if (ctx->mode == EBPF_MODE_PERF) {
    // Initialize perf event counter
    return afl_ebpf_init_perf(ctx);
  } else if (ctx->mode == EBPF_MODE_EXECVE) {
    // Initialize execve tracing
    return afl_ebpf_init_execve(ctx);
  } else {
    WARNF("Unknown eBPF mode: %d, falling back to perf mode", ctx->mode);
    ctx->mode = EBPF_MODE_PERF;
    return afl_ebpf_init_perf(ctx);
  }
}

/* Initialize eBPF perf event counter */
struct afl_ebpf_ctx *afl_ebpf_init_perf(struct afl_ebpf_ctx *ctx) {
  // Load and verify BPF application
  struct afl_ebpf_perf *skel = afl_ebpf_perf__open();
  if (!skel) {
    PFATAL("Failed to open BPF perf skeleton");
    free(ctx);
    return NULL;
  }

  // Load BPF program
  int err = afl_ebpf_perf__load(skel);
  if (err) {
    PFATAL("Failed to load BPF perf program: %d", err);
    afl_ebpf_perf__destroy(skel);
    free(ctx);
    return NULL;
  }

  // Get map file descriptor
  ctx->map_fd = bpf_map__fd(skel->maps.exec_count);
  if (ctx->map_fd < 0) {
    PFATAL("Failed to get perf map file descriptor");
    afl_ebpf_perf__destroy(skel);
    free(ctx);
    return NULL;
  }

  // Initialize map with zero
  __u32 key = 0;
  __u64 value = 0;
  bpf_map_update_elem(ctx->map_fd, &key, &value, BPF_ANY);

  // Store BPF skeleton for later cleanup
  ctx->perf_skel = skel;
  ctx->enabled = true;

  ACTF("eBPF perf event counter initialized");
  return ctx;
}

/* Initialize eBPF execve tracing */
struct afl_ebpf_ctx *afl_ebpf_init_execve(struct afl_ebpf_ctx *ctx) {
  // Load and verify BPF application
  struct afl_ebpf_execve *skel = afl_ebpf_execve__open();
  if (!skel) {
    PFATAL("Failed to open BPF execve skeleton");
    free(ctx);
    return NULL;
  }

  // Load BPF program
  int err = afl_ebpf_execve__load(skel);
  if (err) {
    PFATAL("Failed to load BPF execve program: %d", err);
    afl_ebpf_execve__destroy(skel);
    free(ctx);
    return NULL;
  }

  // Attach tracepoint
  err = afl_ebpf_execve__attach(skel);
  if (err) {
    PFATAL("Failed to attach BPF execve program: %d", err);
    afl_ebpf_execve__destroy(skel);
    free(ctx);
    return NULL;
  }

  // Get map file descriptor for exec_count
  ctx->map_fd = bpf_map__fd(skel->maps.exec_count);
  if (ctx->map_fd < 0) {
    PFATAL("Failed to get execve map file descriptor");
    afl_ebpf_execve__destroy(skel);
    free(ctx);
    return NULL;
  }

  // Get map file descriptor for fuzzer_pid
  ctx->fuzzer_pid_map_fd = bpf_map__fd(skel->maps.fuzzer_pid);
  if (ctx->fuzzer_pid_map_fd < 0) {
    PFATAL("Failed to get fuzzer_pid map file descriptor");
    afl_ebpf_execve__destroy(skel);
    free(ctx);
    return NULL;
  }

  // Initialize exec_count map with zero
  __u32 key = 0;
  __u64 value = 0;
  bpf_map_update_elem(ctx->map_fd, &key, &value, BPF_ANY);

  // Store BPF skeleton for later cleanup
  ctx->execve_skel = skel;
  ctx->enabled = true;

  ACTF("eBPF execve tracing initialized");
  return ctx;
}

/* Attach eBPF program to target process */
int afl_ebpf_attach_to_pid(struct afl_ebpf_ctx *ctx, pid_t pid) {
  if (!ctx || !ctx->enabled) return -1;

  // For execve mode, we just need to set the fuzzer PID
  if (ctx->mode == EBPF_MODE_EXECVE) {
    return afl_ebpf_set_fuzzer_pid(ctx, pid);
  }

  // For perf mode, we need to attach the perf event
  // Configure perf event
  struct perf_event_attr attr = {
    .type = PERF_TYPE_SOFTWARE,
    .size = sizeof(struct perf_event_attr),
    .config = PERF_COUNT_SW_TASK_CLOCK,  // Count CPU time spent by tasks
    .disabled = 1,                       // Start disabled
    .exclude_kernel = 1,                 // Don't count kernel time
    .exclude_hv = 1,                     // Don't count hypervisor time
    .sample_period = 1,                  // Sample after each period
  };

  // Create perf event for the target process
  int perf_fd = perf_event_open(&attr, pid, -1, -1, 0);
  if (perf_fd < 0) {
    WARNF("Failed to create perf event: %d", perf_fd);
    return -1;
  }

  // Attach BPF program to perf event
  int prog_fd = bpf_program__fd(ctx->perf_skel->progs.count_exec);
  if (ioctl(perf_fd, PERF_EVENT_IOC_SET_BPF, prog_fd) < 0) {
    WARNF("Failed to attach BPF program to perf event");
    close(perf_fd);
    return -1;
  }

  // Enable the perf event
  if (ioctl(perf_fd, PERF_EVENT_IOC_ENABLE, 0) < 0) {
    WARNF("Failed to enable perf event");
    close(perf_fd);
    return -1;
  }

  // Store perf event fd for later cleanup
  ctx->perf_fd = perf_fd;
  return 0;
}

/* Set fuzzer PID for execve tracing */
int afl_ebpf_set_fuzzer_pid(struct afl_ebpf_ctx *ctx, pid_t fuzzer_pid) {
  if (!ctx || !ctx->enabled || ctx->fuzzer_pid_map_fd < 0) return -1;
  
  __u32 key = 0;
  pid_t value = fuzzer_pid;
  
  // Update the fuzzer PID in the eBPF map
  if (bpf_map_update_elem(ctx->fuzzer_pid_map_fd, &key, &value, BPF_ANY) != 0) {
    WARNF("Failed to set fuzzer PID in eBPF map");
    return -1;
  }
  
  ACTF("Set fuzzer PID to %d for eBPF execve tracing", fuzzer_pid);
  return 0;
}

/* Clean up eBPF resources */
void afl_ebpf_deinit(struct afl_ebpf_ctx *ctx) {
  if (!ctx) return;

  // Close perf event fd
  if (ctx->perf_fd >= 0) {
    close(ctx->perf_fd);
  }

  // Destroy BPF skeleton based on mode
  if (ctx->mode == EBPF_MODE_PERF && ctx->perf_skel) {
    afl_ebpf_perf__destroy(ctx->perf_skel);
  } else if (ctx->mode == EBPF_MODE_EXECVE && ctx->execve_skel) {
    afl_ebpf_execve__destroy(ctx->execve_skel);
  }

  free(ctx);
}

/* Get execution count from eBPF map */
int afl_ebpf_get_execs(struct afl_ebpf_ctx *ctx) {
  if (!ctx || !ctx->enabled || ctx->map_fd < 0) return -1;

  __u32 key = 0;
  __u64 value;

  if (bpf_map_lookup_elem(ctx->map_fd, &key, &value) != 0) {
    return -1;
  }

  return value;
}

/* Get approximate execution count from eBPF map */
int afl_ebpf_get_approx_execs(struct afl_ebpf_ctx *ctx, double calibration_factor) {
  if (!ctx || !ctx->enabled || ctx->map_fd < 0) return -1;

  __u32 key = 0;
  __u64 value;

  if (bpf_map_lookup_elem(ctx->map_fd, &key, &value) != 0) {
    return -1;
  }

  // Apply calibration factor to convert perf counts to approximate executions
  return (int)(value * calibration_factor);
}

/* Calibrate the perf counter to executions ratio */
double afl_ebpf_calibrate(struct afl_ebpf_ctx *ctx, int num_calibration_runs) {
  if (!ctx || !ctx->enabled || ctx->map_fd < 0) return -1.0;

  __u32 key = 0;
  __u64 start_value, end_value;
  
  // Get starting counter value
  if (bpf_map_lookup_elem(ctx->map_fd, &key, &start_value) != 0) {
    return -1.0;
  }
  
  // Run calibration executions
  // (This would be implemented elsewhere, calling the target program)
  
  // Get ending counter value
  if (bpf_map_lookup_elem(ctx->map_fd, &key, &end_value) != 0) {
    return -1.0;
  }
  
  // Calculate and return calibration factor
  __u64 counter_diff = end_value - start_value;
  return (double)num_calibration_runs / (double)counter_diff;
}

#endif /* USE_EBPF */