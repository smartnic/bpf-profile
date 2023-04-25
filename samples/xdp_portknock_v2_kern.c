#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
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

struct metadata_elem {
  __be16 ethtype;
  u8 ipproto;
  u16 dport;      /* 4 bytes */
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
                            u16 *dport) {
  struct udphdr *udph = data + *nh_off;

  if (udph + 1 > data_end)
    return RET_ERR;

  *nh_off += sizeof(*udph);
  // *sport = ntohs(udph->source);
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
  u16 dport;
  int state_id = 0;
  u32 *value, state;

  value = bpf_map_lookup_elem(&port_state, &state_id);
  if (!value) {
    return XDP_DROP;
  }

  /* Process the previous packets using metadata */
  struct metadata_elem* md;
  int dummy_header_size = sizeof(struct ethhdr);
  void* md_start = data + dummy_header_size;
  u64 md_size = (NUM_PKTS - 1) * sizeof(struct metadata_elem);
  /* safety check of accessing metadata */
  if (md_start + md_size > data_end) {
    return XDP_DROP;
  }
  state = *value;
  /* read metadata element */
  // bpf_printk("initial state: %d", state);
  for (int i = 0; i < NUM_PKTS - 1; i++) {
    md = md_start + i * sizeof(struct metadata_elem);
    if (md->ethtype != htons(ETH_P_IP)) {
      continue;
    }
    if ((md->ipproto != IPPROTO_UDP) &&
        (md->ipproto != IPPROTO_TCP)) {
      continue;
    }
    dport = md->dport;
    state = get_new_state(state, dport);
    // bpf_printk("%d, dport: %d, state: %d", i, dport, state);
  }

  /* Process the assigned packet */
  u64 nh_off = dummy_header_size + md_size;
  struct ethhdr *eth = data + nh_off;
  u16 h_proto;
  int ipproto;
  int rc = XDP_DROP;

  nh_off += sizeof(*eth);
  if (data + nh_off > data_end)
    return rc;

  h_proto = eth->h_proto;
  if (h_proto != htons(ETH_P_IP)) {
    return rc;
  }

  ipproto = parse_ipv4(data, &nh_off, data_end);
  if (ipproto == IPPROTO_UDP) {
    if (parse_udp(data, &nh_off, data_end, &dport) == RET_ERR) {
      return rc;
    }
  } else if (ipproto == IPPROTO_TCP) {
    /* Parse tcp header to get dst_port */
    struct tcphdr *tcp = data + nh_off;
    if (tcp + 1 > data_end)
      return XDP_DROP;
    dport = ntohs(tcp->dest);
  } else {
    /* drop packets that are not udp or tcp */
    return XDP_DROP;
  }

  if (state == OPEN) {
    rc = XDP_PASS;
  }
  state = get_new_state(state, dport);

  *value = state;
  // bpf_printk("pkt, dport: %d, state: %d\n", dport, state);

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
