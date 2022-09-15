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

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, u32);
  __uint(max_entries, 256);
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
  u32 *state;

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

  // Read metadata from payload
  u64 size = (NUM_PKTS - 1) * sizeof(u16);
  if (data + nh_off + size > data_end)
    return rc;

  value = bpf_map_lookup_elem(&port_state, &state_id);
  if (!value) {
    return rc;
  }

  u16 ports[NUM_PKTS - 1];
  for (int i = 0; i < NUM_PKTS - 1; i++) {
    ports[i] = ntohs(*(u16*)(data + nh_off));
    nh_off += sizeof(u16);
  }

  if (ports[0] == PORT_1 && ports[1] == PORT_2 && ports[2] == PORT_3) {
    rc = XDP_PASS;
  }

  return rc;
}

char _license[] SEC("license") = "GPL";
