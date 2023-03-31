/* shared-nothing, use fixed metadata */

#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "xdp_utils.h"

enum state {
  CLOSED_0 = 0,
  CLOSED_1,
  CLOSED_2,
  OPEN,
};

#define SPORT_MIN 53
#define SPORT_MAX 63
#define PORT_1 100
#define PORT_2 101
#define PORT_3 102

#define RET_ERR -1

/* size: 46 bytes */
struct metadata_elem {
  struct ethhdr eth; /* 14 bytes */
  struct iphdr ip;   /* 20 bytes */
  struct udphdr udp; /* 8 bytes */
  u32 pkt_size;      /* 4 bytes */
} __attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 1);
} port_state SEC(".maps");

static int parse_ipv4(void *data, u64 *nh_off, void *data_end) {
  struct iphdr *iph = data + *nh_off;

  if (iph + 1 > data_end)
    return RET_ERR;

  *nh_off += sizeof(*iph);
  return iph->protocol;
}

static inline int parse_udp(void *data, u64 *nh_off, void *data_end,
                            u16 *sport, u16 *dport) {
  struct udphdr *udph = data + *nh_off;

  if (udph + 1 > data_end)
    return RET_ERR;

  *nh_off += sizeof(*udph);
  *sport = ntohs(udph->source);
  *dport = ntohs(udph->dest);
  return 0;
}

static inline u32 get_new_state(u32 state, u16 dport) {
  if (state == CLOSED_0 && dport == PORT_1) {
    state = CLOSED_1;
  } else if (state == CLOSED_1 && dport == PORT_2) {
    state = CLOSED_2;
  } else if (state == CLOSED_2 && dport == PORT_3) {
    state = OPEN;
  } else {
    state = CLOSED_0;
  }
  return state;
}

SEC("xdp_portknock")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth;
  u16 h_proto;
  u64 nh_off;
  int ipproto;
  u16 dport, sport;
  int rc = XDP_DROP;
  int state_id = 0;
  u32 *value, state;
  u16 cur_port;

  struct metadata_elem* md;
  void* md_start = data;
  u64 md_size = (NUM_PKTS - 1) * sizeof(struct metadata_elem);
  /* safety check of accessing metadata */
  if (md_start + md_size > data_end) {
    return XDP_DROP;
  }
  value = bpf_map_lookup_elem(&port_state, &state_id);
  if (!value) {
    return rc;
  }
  state = *value;
  /* read metadata element */
  // bpf_printk("initial state: %d\n", state);
  for (int i = 0; i < NUM_PKTS - 1; i++) {
    md = md_start + i * sizeof(struct metadata_elem);
    cur_port = ntohs(md->udp.dest);
    state = get_new_state(state, cur_port);
    // bpf_printk("%d, dport: %d, state: %d\n", i, cur_port, state);
  }
  // *value = state;
  /* update the start address of the assigned packet */
  data = data + md_size;
  eth = data;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end) {
    return rc;
  }

  h_proto = eth->h_proto;
  if (h_proto != htons(ETH_P_IP)) {
    return rc;
  }

  ipproto = parse_ipv4(data, &nh_off, data_end);
  if (ipproto != IPPROTO_UDP) {
    return rc;
  }

  if (parse_udp(data, &nh_off, data_end, &sport, &dport) == RET_ERR) {
    return rc;
  }
  if (sport < SPORT_MIN || sport > SPORT_MAX) {
    return rc;
  }

  // value = bpf_map_lookup_elem(&port_state, &state_id);
  // if (!value) {
  //   return rc;
  // }
  // state = *value;

  // Process the assigned packet
  if (state == OPEN) {
    rc = XDP_PASS;
  }
  state = get_new_state(state, dport);

  *value = state;

  // bpf_printk("bounce packet back\n");
  /* For all valid packets, bounce them back to the packet generator. */
  data = (void *)(long)ctx->data;
  nh_off = sizeof(*eth);
  if (data + nh_off > data_end) {
    return rc;
  }
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
