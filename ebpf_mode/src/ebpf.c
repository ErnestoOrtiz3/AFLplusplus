#include <unistd.h>
#include "ebpf.h"
#include "debug.h"

afl_ebpf_t *afl_ebpf_init(void) {
  afl_ebpf_t *ebpf = calloc(1, sizeof(afl_ebpf_t));
  if (!ebpf) return NULL;
  
  ebpf->state = AFL_EBPF_NONE;
  ebpf->prog_fd = -1;
  
  return ebpf;
}

void afl_ebpf_destroy(afl_ebpf_t *ebpf) {
  if (!ebpf) return;
  
  if (ebpf->prog_fd >= 0) {
    close(ebpf->prog_fd);
  }
  
  if (ebpf->obj) {
    bpf_object__close(ebpf->obj);
  }
  
  free(ebpf);
}

int afl_ebpf_start(afl_ebpf_t *ebpf) {
  if (!ebpf) return -1;
  if (ebpf->state != AFL_EBPF_READY) return -1;
  
  /* TODO: Implement eBPF program loading and attachment */
  
  ebpf->state = AFL_EBPF_RUNNING;
  return 0;
}

int afl_ebpf_stop(afl_ebpf_t *ebpf) {
  if (!ebpf) return -1;
  if (ebpf->state != AFL_EBPF_RUNNING) return -1;
  
  /* TODO: Implement eBPF program detachment */
  
  ebpf->state = AFL_EBPF_READY;
  return 0;
}
