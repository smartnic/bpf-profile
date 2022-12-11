/*
 * heavy hitter detection
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "xdp_utils.h"

#define MAX_NUM_FLOWS 8
#define MAX_FLOW_BYTES (1 << 10)
#define RET_ERR -1

struct flow_key {
  u8 protocol;
  __be32 src_ip;
  __be32 dst_ip;
  u16 src_port;
  u16 dst_port;
};

struct metadata_elem {
  struct flow_key flow;
  u32 size;
};

struct vecmap_elem {
  struct flow_key flow;
  u64 size;
};

struct vecmap {
  int num;
  struct vecmap_elem elem_list[MAX_NUM_FLOWS];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, struct vecmap);
  __uint(max_entries, 1);
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

void map_insert(struct vecmap* map, struct flow_key* flow, u64 size) {
  /* todo: Need to figure out why (map->num % MAX_NUM_FLOWS) failed in compiling */
  int index = map->num;
  if (index >= 0 && index < MAX_NUM_FLOWS) {
    map->elem_list[index].flow = *flow;
    map->elem_list[index].size = size;
    map->num += 1;
  }
}

u64* map_lookup(struct vecmap* map, struct flow_key* flow) {
  struct vecmap_elem *elem_list = map->elem_list;
  for (int i = 0; i < map->num && i < MAX_NUM_FLOWS; i++) {
    /* 0xf8ffffff is used to zero out the least significant 3 bits as
       they are used for RSS (note: src_ip is be32) */
    if (elem_list[i].flow.protocol == flow->protocol &&
        elem_list[i].flow.src_ip == (flow->src_ip & 0xf8ffffff) &&
        elem_list[i].flow.dst_ip == flow->dst_ip &&
        elem_list[i].flow.src_port == flow->src_port &&
        elem_list[i].flow.dst_port == flow->dst_port) {
      u64 *size = &(elem_list[i].size);
      return size;
    }
  }
  return NULL;
}

SEC("xdp_hhd")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  struct vecmap *value;
  struct flow_key flow = {
    .protocol = 0,
    .src_ip = 0,
    .dst_ip = 0,
    .src_port = 0,
    .dst_port = 0
  };
  struct vecmap_elem *elem;
  struct metadata_elem *md_elem;
  struct flow_key *md_flow;
  u64 pkt_size;
  u16 h_proto;
  u64 nh_off;
  int rc = XDP_DROP;

  nh_off = sizeof(*eth);
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
  /* Zero out the least significant 3 bits as they are used for RSS (note: src_ip is be32) */
  flow.src_ip = iph->saddr & 0xf8ffffff;
  flow.dst_ip = iph->daddr;

  /* Parse udp header to get src_port and dst_port */
  nh_off += sizeof(*iph);
  if (parse_udp(data, nh_off, data_end, &flow.src_port, &flow.dst_port) == RET_ERR) {
    return XDP_DROP;
  }

  int index = 0;
  value = bpf_map_lookup_elem(&my_map, &index);
  if (value) {
    u64 *flow_size_ptr;
    /* Process latest (n-1) packets using metadata */
    nh_off += sizeof(struct udphdr);
    u64 md_size = (NUM_PKTS - 1) * sizeof(struct metadata_elem);
    if (data + nh_off + md_size > data_end)
      return XDP_DROP;

    /* Need to force unroll, otherwise not able to pass the
       kernel verifier because of loop */
#pragma unroll
    for (int i = 0; i < NUM_PKTS - 1; i++) {
      md_elem = data + nh_off;
      md_flow = &md_elem->flow;
      flow_size_ptr = map_lookup(value, md_flow);
      pkt_size = md_elem->size;
      if (flow_size_ptr) {
        *flow_size_ptr += pkt_size;
      } else {
        map_insert(value, md_flow, pkt_size);
      }
      nh_off += sizeof(struct metadata_elem);
    }

    /* Process the current packet */
    pkt_size = data_end - data;
    flow_size_ptr = map_lookup(value, &flow);
    if (flow_size_ptr) {
      *flow_size_ptr += pkt_size;
    } else {
      map_insert(value, &flow, pkt_size);
    }
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
