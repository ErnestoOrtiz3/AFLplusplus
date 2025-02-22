/*
   american fuzzy lop++ - eBPF support
   ----------------------------------

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

 */

#ifdef USE_EBPF

#include <stdlib.h>
#include <unistd.h>

#include "afl-ebpf.h"
#include "debug.h"

/* Initialize eBPF subsystem. Returns NULL on error, pointer to context on success */
struct afl_ebpf_ctx *afl_ebpf_init(void) {

  struct afl_ebpf_ctx *ctx = calloc(1, sizeof(struct afl_ebpf_ctx));
  if (!ctx) {

    WARNF("Failed to allocate eBPF context");
    return NULL;

  }

  ctx->enabled = true;
  ctx->prog_fd = -1;
  ctx->map_fd = -1;

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

#endif /* USE_EBPF */