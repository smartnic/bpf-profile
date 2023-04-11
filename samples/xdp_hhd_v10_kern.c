/*
 * heavy hitter detection
 */
#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "lib/cilium_builtin.h"
#include "lib/cuckoo_hash.h"
#include "xdp_utils.h"

#define MAX_FLOW_BYTES (1 << 10)
#define RET_ERR -1

struct flow_key {
  u8 protocol;
  __be32 src_ip;
  __be32 dst_ip;
  u16 src_port;
  u16 dst_port;
} __attribute__((packed));

struct metadata_elem {
  __be16 ethtype;
  struct flow_key flow;
  u32 size;
} __attribute__((packed));

/* map size: 1024 = 2 * 512 */
BPF_CUCKOO_HASH(flowsize_map, struct flow_key, uint64_t, 512)

static inline int parse_udp(void *data, u64 nh_off, void *data_end,
                            u16 *sport, u16 *dport) {
  struct udphdr *udph = data + nh_off;

  if (udph + 1 > data_end)
    return RET_ERR;

  *sport = ntohs(udph->source);
  *dport = ntohs(udph->dest);
  return 0;
}

SEC("xdp_hhd")
int xdp_prog(struct xdp_md *ctx) {
  // bpf_printk("xdp_prog: receive a packet");
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct metadata_elem *md_elem;
  struct flow_key *md_flow;
  u64 pkt_size;
  u64 nh_off;

  uint32_t zero = 0;
  struct flowsize_map_cuckoo_hash_map *map = bpf_map_lookup_elem(&flowsize_map, &zero);
  if (!map) {
    // bpf_printk("map not found");
    return XDP_DROP;
  }

  u64 *flow_size_ptr;
  /* Process latest (n-1) packets using metadata */
  int dummy_header_size = sizeof(struct ethhdr) + sizeof(struct iphdr);
  int md_offset = dummy_header_size;
  void* md_start = data + md_offset;
  u64 md_size = (NUM_PKTS - 1) * sizeof(struct metadata_elem);
  if (md_start + md_size > data_end)
    return XDP_DROP;

  for (int i = 0; i < NUM_PKTS - 1; i++) {
    md_elem = md_start + i * sizeof(struct metadata_elem);
    if (md_elem->ethtype != htons(ETH_P_IP)) {
      continue;
    }
    md_flow = &md_elem->flow;
    if (md_flow->protocol != IPPROTO_UDP) {
      continue;
    }
    /* Zero out the least significant 4 bits as they are used for RSS (note: src_ip is be32) */
    md_flow->src_ip &= 0xf0ffffff;
    flow_size_ptr = flowsize_map_cuckoo_lookup(map, md_flow);
    pkt_size = md_elem->size;
    if (flow_size_ptr) {
      // bpf_printk("%d: flow in map, update. pkt_size: %ld", i, pkt_size);
      *flow_size_ptr += pkt_size;
    } else {
      // bpf_printk("%d: flow not in map, insert. pkt_size: %ld", i, pkt_size);
      flowsize_map_cuckoo_insert(map, md_flow, &pkt_size);
    }
  }

  /* Process the current packet */
  nh_off = dummy_header_size + md_size;
  struct ethhdr *eth = data + nh_off;
  struct iphdr *iph;
  struct flow_key flow = {
    .protocol = 0,
    .src_ip = 0,
    .dst_ip = 0,
    .src_port = 0,
    .dst_port = 0
  };
  u16 h_proto;
  int rc = XDP_DROP;

  nh_off += sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_DROP;

  h_proto = eth->h_proto;
  if (h_proto != htons(ETH_P_IP)) {
    return XDP_DROP;
  }

  /* Parse ipv4 header to get protocol, src_ip, and dst_ip */
  iph = data + nh_off;
  if (iph + 1 > data_end)
    return XDP_DROP;
  if (iph->protocol != IPPROTO_UDP) {
    return XDP_DROP;
  }
  flow.protocol = IPPROTO_UDP;
  /* Zero out the least significant 4 bits as they are used for RSS (note: src_ip is be32) */
  flow.src_ip = iph->saddr & 0xf0ffffff;
  flow.dst_ip = iph->daddr;

  /* Parse udp header to get src_port and dst_port */
  nh_off += sizeof(*iph);
  if (parse_udp(data, nh_off, data_end, &flow.src_port, &flow.dst_port) == RET_ERR) {
    return XDP_DROP;
  }

  pkt_size = data_end - data;
  flow_size_ptr = flowsize_map_cuckoo_lookup(map, &flow);
  if (flow_size_ptr) {
    // bpf_printk("current: flow in map, update. pkt_size: %ld", pkt_size);
    *flow_size_ptr += pkt_size;
    if (*flow_size_ptr < MAX_FLOW_BYTES) {
      rc = XDP_PASS;
    }
  } else {
    // bpf_printk("current: flow not in map, insert. pkt_size: %ld", pkt_size);
    flowsize_map_cuckoo_insert(map, &flow, &pkt_size);
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
