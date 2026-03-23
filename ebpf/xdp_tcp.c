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

struct {
        __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

SEC("xdp")
int xdp_tcp_parser(struct xdp_md *ctx) {
        void *data_end = (void *)(long)ctx->data_end;
        void *data = (void *)(long)ctx->data;

        struct ethhdr *eth = data;
        if ((void *)eth + sizeof(*eth) > data_end)
                return XDP_PASS;

        __u16 h_proto = bpf_ntohs(eth->h_proto);

        // Simple check: Is it IP (v4 or v6)?
        if (h_proto != ETH_P_IP && h_proto != ETH_P_IPV6)
                return XDP_PASS;

        // We just send the first chunk of EVERY IP packet to userspace.
        // Userspace gopacket will do the heavy lifting of TCP/TLS parsing.
        // This is much more robust than trying to do complex L4 parsing in XDP.
        __u64 flags = BPF_F_CURRENT_CPU | ((__u64)((long)data_end - (long)data) << 32);
        __u32 dummy = 0;
        bpf_perf_event_output(ctx, &events, flags, &dummy, sizeof(dummy));

        return XDP_PASS;
}
