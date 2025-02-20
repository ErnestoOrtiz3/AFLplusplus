#ifndef _AFL_EBPF_H
#define _AFL_EBPF_H

#include "config.h"
#include "types.h"

/* Forward declaration */
struct afl_state;
typedef struct afl_state afl_state_t;

#ifdef HAVE_EBPF
  #include <bpf/libbpf.h>
  #include <bpf/bpf.h>

  // Add check function declaration
  int check_ebpf_available(void);
#endif

// Common structures used by both eBPF and non-eBPF implementations
struct afl_performance_data {
  u64 executions;
  u64 fork_time;
  u64 exec_time;
  u64 context_switches;
  u64 io_operations;
};

#ifdef HAVE_EBPF
  int init_ebpf_stats(void);
  void cleanup_ebpf_stats(void);
  void collect_ebpf_stats(afl_state_t *afl);
#endif

// Common interface for both implementations
void collect_performance_data(afl_state_t *afl);

#endif /* !_AFL_EBPF_H */
