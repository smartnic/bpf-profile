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

static __always_inline void relax_verifier(void) {
  volatile int __maybe_unused id = bpf_get_smp_processor_id();
}

/* limitation: MAX_NUM_FLOWS should be the power of 2 - 1.
  1. 15 is the maximum number due to the complexity issue in verifier.
  2. 1023 is the maximum number due to the limitation of memory allocation.
*/
#define MAX_NUM_FLOWS 15
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

struct vecmap_elem {
  struct flow_key flow;
  u64 size;
};

/* A sorted (increasing) array */
struct vecmap {
  int size;
  struct vecmap_elem elem_list[MAX_NUM_FLOWS + 1];
};

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, struct vecmap);
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

static __always_inline bool map_key_greater(struct flow_key* flow1, struct flow_key* flow2) {
  if (flow1->protocol > flow2->protocol) {
    return true;
  }
  if (flow1->src_ip > flow2->src_ip) {
    return true;
  }
  if (flow1->dst_ip > flow2->dst_ip) {
    return true;
  }
  if (flow1->src_port > flow2->src_port) {
    return true;
  }
  if (flow1->dst_port > flow2->dst_port) {
    return true;
  }
  return false;
}

static __always_inline void map_insert(struct vecmap* map, struct flow_key* flow, u64 size) {
  // Find the position to insert the element
  int map_size = map->size & MAX_NUM_FLOWS;
  int index = map_size;
  for (int i = 0; i < map_size && i < MAX_NUM_FLOWS; i++) {
    bool greater = map_key_greater(&(map->elem_list[i].flow), flow);
    if (greater) {
      index = i;
      break;
    }
  }

  index &= MAX_NUM_FLOWS;
  int j = 0;
  // Shift the elements one space to the right
  /* `for (int i = map->size; i > index; i--)` cannot pass the verifier. */
  for (int i = MAX_NUM_FLOWS - 1; i > 0; i--) {
    if (i > index && i <= map->size) {
      map->elem_list[i].flow = map->elem_list[i - 1].flow;
      map->elem_list[i].size = map->elem_list[i - 1].size;
    }
  }
  // if (index >= 0 && index < MAX_NUM_FLOWS) {
  map->elem_list[index].flow = *flow;
  map->elem_list[index].size = size;
  // }
  map->size += 1;
  if (map->size > MAX_NUM_FLOWS) {
    map->size &= MAX_NUM_FLOWS;
  }
}

#define GT 0
#define EQ 1
#define LT 2
static __always_inline int map_key_comp(struct flow_key* flow1,
                                        struct flow_key* flow2) {
  if (flow1->protocol > flow2->protocol) {
    return GT;
  } else if (flow1->protocol < flow2->protocol) {
    return LT;
  }
  if (flow1->src_ip > flow2->src_ip) {
    return GT;
  } else if (flow1->src_ip < flow2->src_ip) {
    return LT;
  }
  if (flow1->dst_ip > flow2->dst_ip) {
    return GT;
  } else if (flow1->dst_ip < flow2->dst_ip) {
    return LT;
  }
  if (flow1->src_port > flow2->src_port) {
    return GT;
  } else if (flow1->src_port < flow2->src_port) {
    return LT;
  }
  if (flow1->dst_port > flow2->dst_port) {
    return GT;
  } else if (flow1->dst_port < flow2->dst_port) {
    return LT;
  }
  return EQ;
}

static __always_inline u64* map_lookup(struct vecmap* map, struct flow_key* flow) {
  struct vecmap_elem *elem_list = map->elem_list;
  /* Use binary search as map is a sorted array. */
  int low = 0;
  int high = (map->size - 1) & MAX_NUM_FLOWS;
  int mid = 0;
  for (int i = 0; i < MAX_NUM_FLOWS && mid < MAX_NUM_FLOWS; i++) {
    mid = ((low + high) >> 1) & MAX_NUM_FLOWS;
    int comp = map_key_comp(flow, &(elem_list[mid].flow));
    if (comp == LT) {
      high = mid - 1;
    } else if (comp == GT) {
      low = mid + 1;
    } else {
      return &(elem_list[mid].size);
    }
    if (low > high) {
      return NULL;
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
      md_flow->src_ip &= 0xf8ffffff;
#if NUM_PKTS == 4
      flow_size_ptr = map_lookup(value, md_flow);
      relax_verifier();
#else
      relax_verifier();
      flow_size_ptr = map_lookup(value, md_flow);
#endif
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
