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

/* Basic eBPF context structure */
struct afl_ebpf_ctx {
  bool     enabled;
  int      prog_fd;
  int      map_fd;
};

#endif /* USE_EBPF */

#endif /* !_AFL_EBPF_H */