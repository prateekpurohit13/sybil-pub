// go:build ignore

#include <linux/types.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define MAX_TLS_SIZE 1500

struct event {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
  __u32 tls_len;
  __u8 tls_data[MAX_TLS_SIZE];
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024 * 1024);
} ringbuf SEC(".maps");

SEC("xdp")
int xdp_tls_parser(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;

  // Ethernet
  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return XDP_PASS;

  // Only IPv4 for now. IPv6 (ETH_P_IPV6) support can be added later.
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return XDP_PASS;

  // IPv4
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

  // TCP
  __u8 *tcp_bytes = ip_bytes + ip_header_len;
  struct tcphdr *tcp = (struct tcphdr *)tcp_bytes;
  if ((void *)(tcp + 1) > data_end)
    return XDP_PASS;

  __u32 tcp_header_len = (__u32)tcp->doff * 4;
  if (tcp_header_len < sizeof(*tcp))
    return XDP_PASS;
  if ((void *)(tcp_bytes + tcp_header_len) > data_end)
    return XDP_PASS;

  // TLS Client Hello detection
  __u8 *payload = tcp_bytes + tcp_header_len;
  if ((void *)(payload + 6) > data_end)
    return XDP_PASS;

  // payload[0] == 0x16 → TLS Handshake record
  // payload[1] == 0x03 → TLS 1.x (major version)
  // payload[5] == 0x01 → Client Hello handshake type
  if (!(payload[0] == 0x16 && payload[1] == 0x03 && payload[5] == 0x01))
    return XDP_PASS;

  // Build event with metadata + raw TLS bytes
  struct event *e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
  if (!e)
    return XDP_PASS;

  // Connection 4-tuple — useful for logging/correlation in userspace.
  // IPs kept in network byte order; userspace can convert as needed.
  e->src_ip = ip->saddr;
  e->dst_ip = ip->daddr;
  e->src_port = bpf_ntohs(tcp->source);
  e->dst_port = bpf_ntohs(tcp->dest);

  // Copy only the TLS payload (from TLS record header onward).
  long tls_len = data_end - (void *)payload;
  if (tls_len < 0)
    tls_len = 0;
  if (tls_len > MAX_TLS_SIZE)
    tls_len = MAX_TLS_SIZE;
  e->tls_len = (__u32)tls_len;

  for (long i = 0; i < MAX_TLS_SIZE && i < tls_len; i++) {
    if ((void *)(payload + i + 1) > data_end)
      break;
    e->tls_data[i] = payload[i];
  }

  bpf_ringbuf_submit(e, 0);

  return XDP_PASS;
}

struct event *unused_event __attribute__((unused));

char _license[] SEC("license") = "GPL";
