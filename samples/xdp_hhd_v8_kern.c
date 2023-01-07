/*
 * State map is a hash table
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "xdp_utils.h"
#include "xxhash32.h"

#define MAX_NUM_FLOWS 1024
#define MAP_CAPACITY MAX_NUM_FLOWS
#define MAX_FLOW_BYTES (1 << 10)
#define RET_ERR -1

struct flow_key {
  __be32 src_ip;
  __be32 dst_ip;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
} __attribute__((packed));

struct metadata_elem {
  struct flow_key flow;
  u32 size;
};

struct statemap_elem {
  bool is_filled;
  struct flow_key flow;
  u64 size;
};

/* A hash table */
struct statemap {
  int size;
  struct statemap_elem elem_list[MAP_CAPACITY];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, struct statemap);
  __uint(max_entries, 1);
} my_map SEC(".maps");

static __always_inline int parse_udp(void *data, u64 nh_off, void *data_end,
                                     u16 *sport, u16 *dport) {
  struct udphdr *udph = data + nh_off;

  if (udph + 1 > data_end)
    return RET_ERR;

  *sport = ntohs(udph->source);
  *dport = ntohs(udph->dest);
  return 0;
}

static __always_inline bool map_key_equal(struct flow_key* flow1, struct flow_key* flow2) {
  if (flow1->dst_ip == flow2->dst_ip &&
      flow1->src_ip == flow2->src_ip &&
      flow1->dst_port == flow2->dst_port &&
      flow1->src_port == flow2->src_port &&
      flow1->protocol == flow2->protocol)
    return true;

  return false;
}

uint32_t hash_key(struct flow_key* flow) {
  uint32_t hash = xxhash32(flow, sizeof(struct flow_key), 0x2d31e867);
  return hash;
}

struct find_insert_position_ctx {
  struct statemap* map;
  int cur_index;
  int position; // output: the position to insert the new element
};

static int map_insert_find_insert_position(__u32 index, void *data) {
  struct find_insert_position_ctx *ctx = data;
  int i = ctx->cur_index & (MAP_CAPACITY - 1);
  if (!ctx->map->elem_list[i].is_filled) {
    ctx->position = i;
    return 1;
  }
  ctx->cur_index++;
  return 0;
}

static __always_inline void map_insert(struct statemap* map, struct flow_key* flow, u64 size) {
  uint32_t hash = hash_key(flow);
  // Find the position to insert the element
  int index = -1;
  struct find_insert_position_ctx find_pos_ctx = {
    .map = map,
    .cur_index = hash & (MAP_CAPACITY - 1),
    .position = -1
  };
  bpf_loop(MAP_CAPACITY, map_insert_find_insert_position, &find_pos_ctx, 0);
  index = find_pos_ctx.position;
  if (index >= 0 && index < MAX_NUM_FLOWS) {
    map->elem_list[index].is_filled = true;
    map->elem_list[index].flow = *flow;
    map->elem_list[index].size = size;
    map->size += 1;
    if (map->size >= MAP_CAPACITY) {
      map->size &= MAP_CAPACITY - 1;
    }
  }
}

struct map_lookup_search_ctx {
  struct statemap* map;
  struct flow_key* flow;
  int cur_index;
  u64* ptr; // output
};

static int map_lookup_search(__u32 index, void *data) {
  struct map_lookup_search_ctx *ctx = data;
  int i = ctx->cur_index & (MAP_CAPACITY - 1);
  struct statemap_elem *elem = &(ctx->map->elem_list[i]);
  if (elem->is_filled) {
    if (map_key_equal(ctx->flow, &(elem->flow))) {
      ctx->ptr = &(elem->size);
      return 1;
    }
  }
  ctx->cur_index++;
  return 0;
}

static __always_inline u64* map_lookup(struct statemap* map, struct flow_key* flow) {
  uint32_t hash = hash_key(flow);
  struct map_lookup_search_ctx ctx = {
    .map = map,
    .flow = flow,
    .cur_index = hash & (MAP_CAPACITY - 1),
    .ptr = NULL
  };
  bpf_loop(MAP_CAPACITY, map_lookup_search, &ctx, 0);
  return ctx.ptr;
}

SEC("xdp")
int xdp_prog(struct xdp_md* ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  struct statemap *value;
  struct flow_key flow = {
    .protocol = 0,
    .src_ip = 0,
    .dst_ip = 0,
    .src_port = 0,
    .dst_port = 0
  };
  struct statemap_elem *elem;
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
      md_flow->src_ip &= 0xf8ffffff;
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
