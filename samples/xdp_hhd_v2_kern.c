/*
 * heavy hitter detection using local state
 * metadata:
 * | number of pkts | pkt_i length | pkt_i+1 length | ... | pkt_i+x length |
 * number of pkts: number of pkts in the same flow as the assigned packet
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "xdp_utils.h"

#define MAX_NUM_FLOWS 256
#define MAX_FLOW_BYTES (1 << 10)
#define RET_ERR -1

struct flow_key {
  u8 protocol;
  __be32 src_ip;
  __be32 dst_ip;
  u16 src_port;
  u16 dst_port;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, struct flow_key);
  __type(value, u64);
  __uint(max_entries, MAX_NUM_FLOWS);
} my_map SEC(".maps");

static inline int parse_udp(void *data, u64 nh_off, void *data_end,
                            u16 *sport, u16 *dport) {
  struct udphdr *udph = data + nh_off;

  if (udph + 1 > data_end)
    return RET_ERR;

  *sport = ntohs(udph->source);
  *dport = ntohs(udph->dest);
  return 0;
}

SEC("xdp_hdd")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  u64 *value;
  struct flow_key flow = {
    .protocol = 0,
    .src_ip = 0,
    .dst_ip = 0,
    .src_port = 0,
    .dst_port = 0
  };
  u16 h_proto;
  u64 nh_off;
  int rc = XDP_DROP;
  u64 bytes, md_size;
  int num_metadata_pkts;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_DROP;

  h_proto = eth->h_proto;
  if (h_proto != htons(ETH_P_IP)) {
    return XDP_DROP;
  }

  /* Parse ipv4 header */
  iph = data + nh_off;
  if (iph + 1 > data_end)
    return XDP_DROP;
  if (iph->protocol != IPPROTO_UDP) {
    return XDP_DROP;
  }
  flow.protocol = IPPROTO_UDP;
  /* Zero out the least significant 3 bits as they are used for RSS (note: src_ip is be32) */
  flow.src_ip = iph->saddr & 0xf8ffffff;
  flow.dst_ip = iph->daddr;

  nh_off += sizeof(*iph);
  if (parse_udp(data, nh_off, data_end, &flow.src_port, &flow.dst_port) == RET_ERR) {
    return XDP_DROP;
  }

  /* Process latest packets using metadata */
  nh_off += sizeof(struct udphdr);
  md_size = sizeof(u16) + (NUM_PKTS - 1) * sizeof(u32);
  if (data + nh_off + md_size > data_end)
    return XDP_DROP;
  num_metadata_pkts = *(u16*)(data + nh_off);
  nh_off += sizeof(u16);
  bytes = 0;
  for (int i = 1; i < NUM_PKTS && i <= num_metadata_pkts; i++) {
    bytes += *(u32*)(data + nh_off);
    nh_off += sizeof(u32);
  }

  /* Process the assigned packet */
  bytes += data_end - data;

  value = bpf_map_lookup_elem(&my_map, &flow);
  if (value) {
    bytes += *value;
    *value = bytes;
  } else {
    bpf_map_update_elem(&my_map, &flow, &bytes, BPF_NOEXIST);
  }

  if (bytes < MAX_FLOW_BYTES) {
    rc = XDP_PASS;
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
