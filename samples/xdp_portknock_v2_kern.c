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
  struct ethhdr *eth = data;
  u16 h_proto;
  u64 nh_off, md_size;
  int ipproto;
  u16 dport, sport;
  int rc = XDP_DROP;
  int state_id = 0;
  u32 *value, state;
  u16 cur_port;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return rc;

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

  // Safety check of metadata
  md_size = (NUM_PKTS - 1) * sizeof(u16);
  if (data + nh_off + md_size > data_end)
    return rc;

  value = bpf_map_lookup_elem(&port_state, &state_id);
  if (!value) {
    return rc;
  }
  state = *value;

  // Process metadata
  for (int i = 0; i < NUM_PKTS - 1; i++) {
    // todo: remove ntohs() and modify the metadata constructed in scapy
    cur_port = ntohs(*(u16*)(data + nh_off));
    state = get_new_state(state, cur_port);
    nh_off += sizeof(u16);
  }

  // Process the assigned packet
  if (state == OPEN) {
    rc = XDP_PASS;
  }
  state = get_new_state(state, dport);

  *value = state;

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
