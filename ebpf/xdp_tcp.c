// +build ignore

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

char __license[] SEC("license") = "Dual MIT/GPL";

/*
 * Capture contract, keep in sync with internal/capture/capture.go:
 *
 *   - Only IPv4/IPv6 TCP frames are emitted to userspace; every other frame
 *     (ARP, UDP, ICMP, non-TCP fragments, ...) returns XDP_PASS untouched and
 *     never touches the perf ring. This is the in-kernel flood guard.
 *   - The perf sample is a 4-byte metadata prefix (SAMPLE_MARKER) followed by
 *     the raw Ethernet frame (Ethernet + IP + TCP headers and payload),
 *     truncated to MAX_CAPTURE_LEN bytes. The packet bytes are appended by the
 *     kernel because the upper 32 bits of the bpf_perf_event_output() flags
 *     carry the number of bytes to copy from the start of ctx->data; the
 *     helper's data/size arguments may not point into the packet itself.
 *     Userspace strips the fixed prefix before decoding.
 *   - port_config[0] is an optional TCP port filter written by userspace after
 *     load (0 = accept every TCP port). When non-zero, either the source or
 *     the destination port must match.
 *   - IPv6 extension headers are not walked; only a directly following TCP
 *     header is captured. Such ClientHellos remain visible on the pcap
 *     backend.
 */

/* Maximum bytes of each frame appended to a perf sample. 2048 covers standard
 * MTU frames while keeping every sample small. Longer (jumbo/GSO) frames are
 * truncated and may be dropped by the userspace decoder. */
#define MAX_CAPTURE_LEN 2048

/* Fixed 4-byte prefix identifying this sample format. The previous program
 * wrote 0 here; userspace treats both as a prefix (never as packet data). */
#define SAMPLE_MARKER 0x53594231

struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

/* Index 0: TCP port to match (0 = any). Written by userspace after load. */
struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __uint(max_entries, 1);
        __type(key, __u32);
        __type(value, __u32);
} port_config SEC(".maps");

static __always_inline int is_tcp_match(struct ethhdr *eth, void *data_end) {
        __u16 h_proto = bpf_ntohs(eth->h_proto);
        void *l4;
        __u16 sport, dport;

        if (h_proto == ETH_P_IP) {
                struct iphdr *ip = (void *)eth + sizeof(*eth);
                if ((void *)ip + sizeof(*ip) > data_end)
                        return 0;
                if (ip->protocol != IPPROTO_TCP)
                        return 0;
                /* ihl is a 32-bit word count; clang masks it with 0xf. */
                l4 = (void *)ip + ip->ihl * 4;
        } else if (h_proto == ETH_P_IPV6) {
                struct ipv6hdr *ip6 = (void *)eth + sizeof(*eth);
                if ((void *)ip6 + sizeof(*ip6) > data_end)
                        return 0;
                if (ip6->nexthdr != IPPROTO_TCP)
                        return 0;
                l4 = (void *)ip6 + sizeof(*ip6);
        } else {
                return 0;
        }

        struct tcphdr *tcp = l4;
        if ((void *)tcp + sizeof(*tcp) > data_end)
                return 0;

        __u32 key = 0;
        __u32 *match_port = bpf_map_lookup_elem(&port_config, &key);
        if (!match_port || *match_port == 0)
                return 1;

        sport = bpf_ntohs(tcp->source);
        dport = bpf_ntohs(tcp->dest);
        return sport == *match_port || dport == *match_port;
}

SEC("xdp")
int xdp_tcp_parser(struct xdp_md *ctx) {
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;

        struct ethhdr *eth = data;
        if ((void *)eth + sizeof(*eth) > data_end)
                return XDP_PASS;

        if (!is_tcp_match(eth, data_end))
                return XDP_PASS;

        __u32 pkt_len = (__u32)((long)data_end - (long)data);
        if (pkt_len > MAX_CAPTURE_LEN)
                pkt_len = MAX_CAPTURE_LEN;

        /* Prefix + kernel-appended packet bytes. */
        __u32 meta = SAMPLE_MARKER;
        __u64 flags = BPF_F_CURRENT_CPU | ((__u64)pkt_len << 32);
        bpf_perf_event_output(ctx, &events, flags, &meta, sizeof(meta));

        return XDP_PASS;
}
