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


struct exec_stats {
  __u64 total_execs; // Counter for total executions tracked by eBPF
};

/* eBPF context structure */
struct afl_ebpf_ctx {
  bool enabled;      /* Whether eBPF support is enabled */
  int  prog_fd;     /* File descriptor for eBPF program */
  int  map_fd;      /* File descriptor for eBPF map */
  struct exec_stats stats; // Structure to hold the execution statistics
};


/* Function declarations */
struct afl_ebpf_ctx *afl_ebpf_init(void); // Initialize eBPF context
void afl_ebpf_deinit(struct afl_ebpf_ctx *ctx); // Cleanup eBPF resources
int afl_ebpf_get_execs(struct afl_ebpf_ctx *ctx); // Get execution count

#endif /* USE_EBPF */

#endif /* !_AFL_EBPF_H */