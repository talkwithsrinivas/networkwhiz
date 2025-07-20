#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/in.h> // for IPPROTO_UDP

#define ETH_P_IP 0x0800
#define DNS_PORT 53
#define MAX_DOMAIN_LEN 256
#define LOCAL_IP 0x4a9cea0a // 10.156.238.74 in hex, little-endian
#define MAX_QNAME_BYTES 64

struct dns_event {
    char domain[MAX_DOMAIN_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

SEC("xdp")
int xdp_dns_response_only(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(eth->h_proto) != ETH_P_IP)
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    if (ip->daddr != bpf_htonl(LOCAL_IP))
        return XDP_PASS;

    int ip_hdr_len = ip->ihl * 4;
    struct udphdr *udp = (void *)((char *)ip + ip_hdr_len);
    if ((void *)(udp + 1) > data_end)
        return XDP_PASS;

    if (bpf_ntohs(udp->source) != DNS_PORT)
        return XDP_PASS;

    unsigned char *dns = (void *)(udp + 1);
    if (dns + 12 > (unsigned char *)data_end)
        return XDP_PASS;

    if (!(dns[2] & 0x80))
        return XDP_PASS;

    unsigned char *ptr = dns + 12;
    struct dns_event event = {};
    int offset = 0;

    #pragma unroll
    for (int i = 0; i < MAX_QNAME_BYTES; i++) {
        if (ptr + i + 1 > (unsigned char *)data_end)
            break;

        __u8 c = ptr[i];
        if (c == 0) {
            if (offset < MAX_DOMAIN_LEN)
                event.domain[offset] = '\0';
            break;
        }

        if (offset < MAX_DOMAIN_LEN - 1)
            event.domain[offset++] = c;
    }

    if (offset > 0 && event.domain[offset - 1] == '.')
        event.domain[offset - 1] = '\0';
    else if (offset < MAX_DOMAIN_LEN)
        event.domain[offset] = '\0';

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return XDP_PASS;
}

char __license[] SEC("license") = "GPL";


