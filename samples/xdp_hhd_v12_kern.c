/*
 * heavy hitter detection (RSS++ version)
 */
#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_utils.h"

#define MAX_NUM_FLOWS 1024
#define MAX_FLOW_BYTES (1 << 10)
#define RET_ERR -1

struct flow_key {
  __u8 protocol;
  __be32 src_ip;
  __be32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct flow_key);
  __type(value, __u64);
  __uint(max_entries, MAX_NUM_FLOWS);
} my_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 512);
} count_map SEC(".maps");

static inline int parse_udp(void *data, __u64 nh_off, void *data_end,
                            __u16 *sport, __u16 *dport) {
  struct udphdr *udph = data + nh_off;

  if (udph + 1 > data_end)
    return RET_ERR;

  *sport = bpf_ntohs(udph->source);
  *dport = bpf_ntohs(udph->dest);
  return 0;
}

SEC("xdp_hdd")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  __u64 *value, bytes_before;
  struct flow_key flow = {
    .protocol = 0,
    .src_ip = 0,
    .dst_ip = 0,
    .src_port = 0,
    .dst_port = 0
  };
  __u16 h_proto;
  __u64 nh_off;
  int rc = XDP_DROP;
  bool need_session_table = false;
  bool remove_session_table = false;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_DROP;

  /* RSS++ section start */
  __u64 *count_map_value;

  __u32 hash_id = ctx->hash % 256; //TODO : change according to the current number of queue. But the map size would need to be changed too. Therefore it would be more practical to simply recompile this file with a different parameter.

  count_map_value = bpf_map_lookup_elem(&count_map, &hash_id);
  if (count_map_value)
      __sync_fetch_and_add(count_map_value, 1);
  
  /* RSS++ section end */

  h_proto = eth->h_proto;
  if (h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_DROP;
  }

  /* Parse ipv4 header to get protocol, src_ip, and dst_ip */
  iph = data + nh_off;
  if (iph + 1 > data_end)
    return XDP_DROP;

  flow.protocol = iph->protocol;
  /* Zero out the least significant 4 bits as they are used for RSS (note: src_ip is be32) */
  flow.src_ip = iph->saddr;
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
    flow.src_port = bpf_ntohs(tcp->source);
    flow.dst_port = bpf_ntohs(tcp->dest);
    // check if entry needs to be removed
    remove_session_table = tcp->fin;
    // bpf_printk("fin_flag (remove entry): %s", remove_session_table ? "true" : "false");
    need_session_table = tcp->syn;
  } else {
    /* drop packets that are not udp or tcp */
    return XDP_DROP;
  }

  /* Calculate packet length */
  __u64 bytes = data_end - data;
  value = bpf_map_lookup_elem(&my_map, &flow);
  if (value) {
    // bpf_printk("map hit");
    bytes_before = __sync_fetch_and_add(value, bytes);
    bytes += bytes_before;
    if (remove_session_table) {
      // bpf_printk("map remove");
      bpf_map_delete_elem(&my_map, &flow);
    }
  } else {
    // bpf_printk("map miss");
    if (need_session_table) {
      // bpf_printk("map insert");
      bpf_map_update_elem(&my_map, &flow, &bytes, BPF_NOEXIST);
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