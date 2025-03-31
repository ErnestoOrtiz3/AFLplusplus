// Modern XDP program with BTF-based map definitions
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>  // For IPPROTO_TCP
#include <bpf/bpf_endian.h> // For bpf_ntohs

// Define maps using BTF-based approach
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 3);
    __type(key, __u32);
    __type(value, __u64);
} stats SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, __u16);
    __type(value, __u8);
} afl_ports SEC(".maps");

// Stats indices
#define STAT_TOTAL    0
#define STAT_AFL      1
#define STAT_NON_AFL  2

SEC("xdp")
int xdp_afl_classifier(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    // Increment total packet counter
    __u32 key = STAT_TOTAL;
    __u64 *value = bpf_map_lookup_elem(&stats, &key);
    if (value)
        (*value)++;
    
    // Parse Ethernet header
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        goto non_afl;
    
    // Check if it's an IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        goto non_afl;
    
    // Parse IP header
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        goto non_afl;
    
    // Check if it's TCP
    if (ip->protocol != IPPROTO_TCP)
        goto non_afl;
    
    // Parse TCP header
    struct tcphdr *tcp = (void *)(ip + 1);
    if ((void *)(tcp + 1) > data_end)
        goto non_afl;
    
    // Get destination port
    __u16 dport = bpf_ntohs(tcp->dest);
    
    // Check if port is in our AFL ports map
    __u8 *found = bpf_map_lookup_elem(&afl_ports, &dport);
    if (found && *found) {
        // It's an AFL port, increment AFL counter
        key = STAT_AFL;
        value = bpf_map_lookup_elem(&stats, &key);
        if (value)
            (*value)++;
        return XDP_PASS;
    }
    
non_afl:
    // Increment non-AFL counter
    key = STAT_NON_AFL;
    value = bpf_map_lookup_elem(&stats, &key);
    if (value)
        (*value)++;
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
