// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

SEC("xdp")
int xdp_afl_pass(struct xdp_md *ctx)
{
    // Simplest possible XDP program - just pass all packets
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
