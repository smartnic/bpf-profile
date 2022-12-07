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

struct element {
  struct flow_key flow;
  u64 bytes;
};

struct map_value {
  struct element elem_list[MAX_NUM_FLOWS];
};

/* The size of value should <= the stack size (512B), otherwise not able to
   use map update to insert a new element
*/
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct flow_key);
  __type(value, struct map_value);
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

SEC("xdp_hdd")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  struct map_value *value;
  u64 *bytes_before;
  struct flow_key flow = {
    .protocol = 0,
    .src_ip = 0,
    .dst_ip = 0,
    .src_port = 0,
    .dst_port = 0
  };
  struct element *elem;
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

  /* Calculate packet length */
  u64 bytes = data_end - data;
  value = bpf_map_lookup_elem(&my_map, &flow);
  if (value) {
    for (int i = 0; i < NUM_PKTS; i++) {
      elem = &value->elem_list[i];
      /* Read flow by using a dummy check */
      if (elem->flow.protocol != 0 ||
          elem->flow.src_ip != 0 ||
          elem->flow.dst_ip != 0 ||
          elem->flow.src_port != 0 ||
          elem->flow.dst_port != 0) {
        return XDP_DROP;
      }
      /* Read and update state */
      elem->bytes += 1;
    }
  } else {
    struct element elem_list[MAX_NUM_FLOWS];
    memset(elem_list, 0, sizeof(struct element) * MAX_NUM_FLOWS);
    bpf_map_update_elem(&my_map, &flow, &elem_list, BPF_NOEXIST);
  }
  if (bytes < MAX_FLOW_BYTES) {
    rc = XDP_PASS;
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
