#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <netinet/in.h>
#include <bpf_helpers.h> 

struct bpf_map_def {
      unsigned int type;
      unsigned int key_size;
      unsigned int value_size;
      unsigned int max_entries;
      unsigned int map_flags;
};

struct bpf_map_def SEC("maps") port_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .key_size    = sizeof(__u32),
    .value_size  = sizeof(__u32),
    .max_entries = 1,
};

SEC("xdp_prog")
int xdp_drop_port(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    // Ethernet header check
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        return XDP_PASS;
    }

    // IPv4 check
    if (eth->h_proto != htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // IP header check
    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }

    // TCP check
    if (ip->protocol != IPPROTO_TCP) {
        return XDP_PASS;
    }

    // TCP header check
    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end) {
        return XDP_PASS;
    }

    // Retrieve port from map (if it exists)
    __u32 key = 0;
    __u32 *port = bpf_map_lookup_elem(&port_map, &key);
    if (!port) {
        return XDP_PASS; // No port in map, pass traffic
    }

    // Drop if destination port matches
    if (tcp->dest == htons(*port)) {
        return XDP_DROP;
    }

    return XDP_PASS;
}