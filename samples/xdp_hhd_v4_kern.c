/*
 * heavy hitter detection (flow affinity using cuckoo hash)
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include "xdp_utils.h"

#define MAX_NUM_FLOWS 1024
#define MAX_FLOW_BYTES (1 << 10)
#define RET_ERR -1

#include "lib/cilium_builtin.h"
#include "lib/cuckoo_hash.h"

struct flow_key {
  u8 protocol;
  __be32 src_ip;
  __be32 dst_ip;
  u16 src_port;
  u16 dst_port;
} __attribute__((packed));

/* map size: 1024 = 2 * 512 */
BPF_CUCKOO_HASH(flowsize_map, struct flow_key, u64, 512)

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
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  u64 *value;
  struct flow_key flow = {
    .protocol = 0,
    .src_ip = 0,
    .dst_ip = 0,
    .src_port = 0,
    .dst_port = 0
  };
  u16 h_proto;
  u64 nh_off;
  int rc = XDP_DROP;
  bool need_session_table = false;
  bool remove_session_table = false;

  uint32_t zero = 0;
  struct flowsize_map_cuckoo_hash_map *map = bpf_map_lookup_elem(&flowsize_map, &zero);
  if (!map) {
    // bpf_printk("map not found");
    return XDP_DROP;
  }

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

  flow.protocol = iph->protocol;
  /* Zero out the least significant 4 bits as they are used for RSS (note: src_ip is be32) */
  flow.src_ip = iph->saddr & 0xf0ffffff;
  flow.dst_ip = iph->daddr;

  /* Parse udp header to get src_port and dst_port */
  nh_off += sizeof(*iph);
  if (iph->protocol == IPPROTO_UDP) {
    if (parse_udp(data, nh_off, data_end, &flow.src_port, &flow.dst_port) == RET_ERR) {
      return XDP_DROP;
    }
    need_session_table = true;
  } else if (iph->protocol == IPPROTO_TCP) {
    /* Parse tcp header to get src_port and dst_port */
    struct tcphdr *tcp = data + nh_off;
    if (tcp + 1 > data_end)
      return XDP_DROP;
    flow.src_port = ntohs(tcp->source);
    flow.dst_port = ntohs(tcp->dest);
    // check if entry needs to be removed
    remove_session_table = tcp->fin;
    // bpf_printk("fin_flag (remove entry): %s", remove_session_table ? "true" : "false");
    need_session_table = tcp->syn;
  } else {
    /* drop packets that are not udp or tcp */
    return XDP_DROP;
  }

  /* Calculate packet length */
  u64 bytes = data_end - data;
  value = flowsize_map_cuckoo_lookup(map, &flow);
  if (value) {
    // bpf_printk("map hit");
    bytes += *value;
    *value = bytes;
    if (remove_session_table) {
      // bpf_printk("map remove");
      flowsize_map_cuckoo_delete(map, &flow);
    }
  } else {
    // bpf_printk("map miss");
    if (need_session_table) {
      // bpf_printk("map insert");
      flowsize_map_cuckoo_insert(map, &flow, &bytes);
    }
  }
  if (bytes < MAX_FLOW_BYTES) {
    rc = XDP_PASS;
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
