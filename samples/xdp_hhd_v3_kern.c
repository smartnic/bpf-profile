/*
 * heavy hitter detection using local state
 * metadata element: | pkt_i flow | pkt_i length |
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

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

struct hash_elem {
  u64 bytes;
};

struct metadata_elem {
  struct flow_key flow;
  u32 bytes;
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, struct flow_key);
  __type(value, struct hash_elem);
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
  struct hash_elem *value;
  struct flow_key flow = {
    .protocol = 0,
    .src_ip = 0,
    .dst_ip = 0,
    .src_port = 0,
    .dst_port = 0
  };
  struct flow_key *flow_tmp;
  u16 h_proto;
  u64 nh_off;
  u64 bytes, md_size;
  struct metadata_elem *md_elem;

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
  flow.src_ip = iph->saddr;
  flow.dst_ip = iph->daddr;

  nh_off += sizeof(*iph);
  if (parse_udp(data, nh_off, data_end, &flow.src_port, &flow.dst_port) == RET_ERR) {
    return XDP_DROP;
  }

  /* Process latest (n-1) packets using metadata */
  nh_off += sizeof(struct udphdr);
  md_size = (NUM_PKTS - 1) * sizeof(struct metadata_elem);
  if (data + nh_off + md_size > data_end)
    return XDP_DROP;
  bytes = 0;
  for (int i = 0; i < NUM_PKTS - 1; i++) {
    md_elem = data + nh_off;
    flow_tmp = &md_elem->flow;
    if (flow_tmp->protocol == flow.protocol &&
        flow_tmp->src_ip == flow.src_ip &&
        flow_tmp->dst_ip == flow.dst_ip &&
        flow_tmp->src_port == flow.src_port &&
        flow_tmp->dst_port == flow.dst_port) {
      bytes += (u64)md_elem->bytes;
    }
    nh_off += sizeof(struct metadata_elem);
  }

  /* Process the assigned packet */
  /* Calculate packet length */
  bytes += data_end - data;

  value = bpf_map_lookup_elem(&my_map, &flow);
  if (value) {
    bytes += value->bytes;
    value->bytes = bytes;
  } else {
    bpf_map_update_elem(&my_map, &flow, &bytes, BPF_NOEXIST);
  }

  if (bytes < MAX_FLOW_BYTES) {
    return XDP_PASS;
  }
  return XDP_DROP;
}

char _license[] SEC("license") = "GPL";