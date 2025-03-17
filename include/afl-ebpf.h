/*
   american fuzzy lop++ - eBPF support header
   -----------------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#ifndef _AFL_EBPF_H
#define _AFL_EBPF_H

#ifdef USE_EBPF

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdbool.h>
#include <linux/bpf.h>
#include <sys/types.h>

// Forward declarations for skeleton structures
struct afl_ebpf_perf;
struct afl_ebpf_execve;

// eBPF modes
#define EBPF_MODE_PERF   0  // Perf event counter
#define EBPF_MODE_EXECVE 1  // Execve tracing

/* eBPF context structure */
struct afl_ebpf_ctx {
  bool enabled;      /* Whether eBPF support is enabled */
  int  mode;         /* eBPF mode (perf or execve) */
  int  prog_fd;      /* File descriptor for eBPF program */
  int  map_fd;       /* File descriptor for exec_count map */
  int  fuzzer_pid_map_fd; /* File descriptor for fuzzer_pid map */
  int  perf_fd;      /* File descriptor for perf event */
  
  // Mode-specific skeleton references
  union {
    struct afl_ebpf_perf *perf_skel;     /* BPF perf skeleton reference */
    struct afl_ebpf_execve *execve_skel; /* BPF execve skeleton reference */
  };
};

/* Function declarations */
struct afl_ebpf_ctx *afl_ebpf_init(const char *target_path);
struct afl_ebpf_ctx *afl_ebpf_init_perf(struct afl_ebpf_ctx *ctx);
struct afl_ebpf_ctx *afl_ebpf_init_execve(struct afl_ebpf_ctx *ctx);
int afl_ebpf_attach_to_pid(struct afl_ebpf_ctx *ctx, pid_t pid);
int afl_ebpf_set_fuzzer_pid(struct afl_ebpf_ctx *ctx, pid_t fuzzer_pid);
void afl_ebpf_deinit(struct afl_ebpf_ctx *ctx);
int afl_ebpf_get_execs(struct afl_ebpf_ctx *ctx);
int afl_ebpf_get_approx_execs(struct afl_ebpf_ctx *ctx, double calibration_factor);
double afl_ebpf_calibrate(struct afl_ebpf_ctx *ctx, int num_calibration_runs);

#endif /* USE_EBPF */

#endif /* !_AFL_EBPF_H */