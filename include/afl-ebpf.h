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

/* eBPF context structure */
struct afl_ebpf_ctx {
  bool enabled;      /* Whether eBPF support is enabled */
  int  prog_fd;     /* File descriptor for eBPF program */
  int  map_fd;      /* File descriptor for eBPF map */
};


/* Function declarations */
struct afl_ebpf_ctx *afl_ebpf_init(void);
void afl_ebpf_deinit(struct afl_ebpf_ctx *ctx);
#endif /* USE_EBPF */

#endif /* !_AFL_EBPF_H */