#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

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

struct array_elem {
  u32 state;
  struct bpf_spin_lock lock;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, struct array_elem);
  __uint(max_entries, 256);
} port_state SEC(".maps");

static int parse_ipv4(void *data, u64 *nh_off, void *data_end) {
  struct iphdr *iph = data + *nh_off;

  if (iph + 1 > data_end)
    return RET_ERR;

  *nh_off += sizeof(*iph);
  return iph->protocol;
}

static inline int parse_udp(void *data, u64 nh_off, void *data_end,
                            u16 *sport, u16 *dport) {
  struct udphdr *udph = data + nh_off;

  if (udph + 1 > data_end)
    return RET_ERR;

  *sport = ntohs(udph->source);
  *dport = ntohs(udph->dest);
  return 0;
}

static inline void swap_src_dst_mac(void *data) {
  unsigned short *p = data;
  unsigned short dst[3];

  dst[0] = p[0];
  dst[1] = p[1];
  dst[2] = p[2];
  p[0] = p[3];
  p[1] = p[4];
  p[2] = p[5];
  p[3] = dst[0];
  p[4] = dst[1];
  p[5] = dst[2];
}

SEC("xdp_portknock")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct array_elem *value;
  u16 h_proto;
  u64 nh_off;
  int ipproto;
  u16 dport, sport;
  int rc = XDP_DROP;
  int state_id = 0;

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

  if (parse_udp(data, nh_off, data_end, &sport, &dport) == RET_ERR) {
    return rc;
  }
  if (sport < SPORT_MIN || sport > SPORT_MAX) {
    return rc;
  }

  value = bpf_map_lookup_elem(&port_state, &state_id);
  if (!value) {
    return rc;
  }
  bpf_spin_lock(&value->lock);
  if (value->state == OPEN) {
    rc = XDP_PASS;
  }
  if (value->state == CLOSED_0 && dport == PORT_1) {
    value->state = CLOSED_1;
  } else if (value->state == CLOSED_1 && dport == PORT_2) {
    value->state = CLOSED_2;
  } else if (value->state == CLOSED_2 && dport == PORT_3) {
    value->state = OPEN;
  } else {
    value->state = CLOSED_0;
  }
  bpf_spin_unlock(&value->lock);

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
