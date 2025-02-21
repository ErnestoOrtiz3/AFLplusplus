#ifndef __AFL_EBPF_H
#define __AFL_EBPF_H

#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "types.h"

/* eBPF program states */
typedef enum {
  AFL_EBPF_NONE,
  AFL_EBPF_READY,
  AFL_EBPF_RUNNING,
  AFL_EBPF_ERROR
} afl_ebpf_state_t;

/* Main eBPF context structure */
typedef struct afl_ebpf {
  afl_ebpf_state_t state;
  struct bpf_object *obj;
  int prog_fd;
  /* Add more fields as needed */
} afl_ebpf_t;

/* Function declarations */
afl_ebpf_t *afl_ebpf_init(void);
void afl_ebpf_destroy(afl_ebpf_t *ebpf);
int afl_ebpf_start(afl_ebpf_t *ebpf);
int afl_ebpf_stop(afl_ebpf_t *ebpf);

#endif /* __AFL_EBPF_H */