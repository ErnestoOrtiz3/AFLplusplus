/*
   american fuzzy lop++ - eBPF support
   ----------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#ifdef USE_EBPF

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/bpf.h>
#include <bpf/libbpf.h>
#include "afl-ebpf.h"
#include "debug.h"


// Generated from afl-ebpf-execve.c
#include "afl-ebpf-execve.skel.h"

/* Initialize eBPF subsystem. Returns NULL on error, pointer to context on success */
struct afl_ebpf_ctx *afl_ebpf_init(void) {

  struct afl_ebpf_ctx *ctx = calloc(1, sizeof(struct afl_ebpf_ctx));
  if (!ctx) {

    WARNF("Failed to allocate eBPF context");
    return NULL;

  }

  // Open and load BPF program
  struct afl_ebpf_execve *skel = afl_ebpf_execve__open_and_load();
  if (!skel) {
      PFATAL("Failed to open and load BPF program");
      free(ctx);
      return NULL;
  }

  // Attach tracepoint
  int err = afl_ebpf_execve__attach(skel);
  if (err) {
      PFATAL("Failed to attach BPF program");
      afl_ebpf_execve__destroy(skel);
      free(ctx);
      return NULL;
  }

  ctx->enabled = true;
  ctx->prog_fd = bpf_program__fd(skel->progs.trace_execve_enter);
  ctx->map_fd = bpf_map__fd(skel->maps.exec_count);

  ACTF("eBPF context initialized");
  return ctx;

}

/* Clean up eBPF resources */
void afl_ebpf_deinit(struct afl_ebpf_ctx *ctx) {

  if (!ctx) { return; }

  if (ctx->prog_fd >= 0) { close(ctx->prog_fd); }
  if (ctx->map_fd >= 0) { close(ctx->map_fd); }

  free(ctx);

}


int afl_ebpf_get_execs(struct afl_ebpf_ctx *ctx) {
  if (!ctx || !ctx->enabled) return -1;

  __u32 key = 0;
  __u64 value;

  if (bpf_map_lookup_elem(ctx->map_fd, &key, &value) != 0) {
      return -1;
  }

  return value;
}

#endif /* USE_EBPF */