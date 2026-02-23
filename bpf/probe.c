#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/types.h>

#define MAX_PKT_SIZE 1024

struct event {
  __u32 pkt_len;
  __u8 pkt_data[MAX_PKT_SIZE];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} ringbuf SEC(".maps");

SEC("xdp")
int xdp_tls_parser(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  __u8 *ip_bytes = (__u8 *)(eth + 1);
  struct iphdr *ip = (struct iphdr *)ip_bytes;
  if ((void *)(ip + 1) > data_end)
    return XDP_PASS;

  if (ip->protocol != IPPROTO_TCP)
    return XDP_PASS;

  __u32 ip_header_len = (__u32)ip->ihl * 4;
  if (ip_header_len < sizeof(*ip))
    return XDP_PASS;
  if ((void *)(ip_bytes + ip_header_len) > data_end)
    return XDP_PASS;

  __u8 *tcp_bytes = ip_bytes + ip_header_len;
  struct tcphdr *tcp = (struct tcphdr *)tcp_bytes;
  if ((void *)(tcp + 1) > data_end)
    return XDP_PASS;

  __u32 tcp_header_len = (__u32)tcp->doff * 4;
  if (tcp_header_len < sizeof(*tcp))
    return XDP_PASS;
  if ((void *)(tcp_bytes + tcp_header_len) > data_end)
    return XDP_PASS;

  __u8 *payload = tcp_bytes + tcp_header_len;
  if ((void *)(payload + 6) > data_end)
    return XDP_PASS;

  // 5. Fingerprint TLS Client Hello
  // payload[0] == 0x16 (Handshake Record)
  // payload[1] == 0x03 (TLS 1.x)
  // payload[5] == 0x01 (Client Hello)
  if (payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01) {

    struct event *e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e)
      return XDP_PASS;

    __u32 len = data_end - data;
    __u32 copy_len = len;

    if (copy_len > MAX_PKT_SIZE) {
      copy_len = MAX_PKT_SIZE;
    }
    e->pkt_len = copy_len;

    for (__u32 i = 0; i < MAX_PKT_SIZE; i++) {
      if (i >= copy_len)
        break;
      if ((void *)data + i + 1 > data_end)
        break;
      e->pkt_data[i] = *((__u8 *)data + i);
    }

    bpf_ringbuf_submit(e, 0);
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
