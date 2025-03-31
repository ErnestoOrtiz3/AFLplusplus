// Simplified XDP program for AFL network fuzzing without BTF requirements
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// Legacy map definitions that don't require BTF
struct bpf_map_def SEC("maps") afl_ports = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u16),
    .value_size = sizeof(__u8),
    .max_entries = 64,
};

struct bpf_map_def SEC("maps") stats = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 4,
};

// Stats indices
#define STAT_TOTAL  0
#define STAT_AFL    1
#define STAT_NON_AFL 2

SEC("xdp")
int xdp_afl_classify(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct ethhdr *eth = data;
    
    // Update total packet count
    __u32 key = STAT_TOTAL;
    __u64 *value = bpf_map_lookup_elem(&stats, &key);
    if (value)
        (*value)++;
    
    // Check if we have enough data for Ethernet header
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    // Check if it's an IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = (void *)(eth + 1);
    
    // Check if we have enough data for IP header
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    
    // Check if it's TCP or UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP)
        return XDP_PASS;
    
    __u16 port = 0;
    
    // Extract port based on protocol
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        
        // Check if we have enough data for TCP header
        if ((void *)(tcp + 1) > data_end)
            return XDP_PASS;
        
        port = bpf_ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        
        // Check if we have enough data for UDP header
        if ((void *)(udp + 1) > data_end)
            return XDP_PASS;
        
        port = bpf_ntohs(udp->dest);
    }
    
    // Check if this is an AFL port
    __u8 *is_afl = bpf_map_lookup_elem(&afl_ports, &port);
    
    if (is_afl && *is_afl) {
        // Update AFL packet count
        key = STAT_AFL;
        value = bpf_map_lookup_elem(&stats, &key);
        if (value)
            (*value)++;
        
        // This is an AFL packet, pass it through
        return XDP_PASS;
    } else {
        // Update non-AFL packet count
        key = STAT_NON_AFL;
        value = bpf_map_lookup_elem(&stats, &key);
        if (value)
            (*value)++;
        
        // This is not an AFL packet, pass it through
        return XDP_PASS;
    }
}

char _license[] SEC("license") = "GPL";