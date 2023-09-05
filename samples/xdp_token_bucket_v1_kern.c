/* rate limiting on each flow using token bucket (single token rate)
 * flow: 5 tuples
 * shared-state approach
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
/* (1 >> TOKEN_RATE) packets per nanosecond */
#define TOKEN_RATE 10
#define MAX_TOKEN 16 /* MAX_TOKEN >= token_needed */
#define RET_ERR -1

struct flow_key {
  __be32 src_ip;
  __be32 dst_ip;
  u16 src_port;
  u16 dst_port;
  u8 protocol;
} __attribute__((packed));

struct token_elem {
  u32 num;        /* number of tokens */
  u64 last_time;  /* flow's last arriving time */
  struct bpf_spin_lock lock;
};

// map: key: flow;
// value: (1) # of tokens; (2) last time stamp
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, struct flow_key);
  __type(value, struct token_elem);
  __uint(max_entries, MAX_NUM_FLOWS);
} token_map SEC(".maps");

static inline int parse_udp(void *data, u64 nh_off, void *data_end,
                            u16 *sport, u16 *dport) {
  struct udphdr *udph = data + nh_off;

  if (udph + 1 > data_end)
    return RET_ERR;

  *sport = ntohs(udph->source);
  *dport = ntohs(udph->dest);
  return 0;
}

SEC("xdp")
int xdp_prog(struct xdp_md* ctx) {
  u64 cur_time = bpf_ktime_get_ns();
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  struct flow_key flow = {
    .protocol = 0,
    .src_ip = 0,
    .dst_ip = 0,
    .src_port = 0,
    .dst_port = 0
  };
  u16 h_proto;
  u64 nh_off;
  struct token_elem *token = NULL;
  int rc = XDP_DROP;
  bool remove_session_table = false;

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
  /* Zero out the least significant 4 bits as they are
     used for RSS (note: src_ip is be32) */
  flow.src_ip = iph->saddr & 0xf0ffffff;
  flow.dst_ip = iph->daddr;
  nh_off += sizeof(*iph);
  if (iph->protocol == IPPROTO_UDP) {
    /* Parse udp header to get src_port and dst_port */
    if (parse_udp(data, nh_off, data_end, &flow.src_port,
                  &flow.dst_port) == RET_ERR) {
      return XDP_DROP;
    }
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
  } else {
    /* drop packets that are not udp or tcp */
    return XDP_DROP;
  }

  u32 token_needed = 1;
  // bpf_printk("cur_time: %lld\n", cur_time);
  token = bpf_map_lookup_elem(&token_map, &flow);
  if (!token) {
    // bpf_printk("token_map miss");
    /* configure flow initial state in the map */
    rc = XDP_PASS;
    if (!remove_session_table) {
      u32 token_remain = MAX_TOKEN - token_needed;
      struct token_elem elem;
      __builtin_memset(&elem, 0, sizeof(elem));
      elem.num = token_remain;
      elem.last_time = cur_time;
      // bpf_printk("token_map insert");
      bpf_map_update_elem(&token_map, &flow, &elem, BPF_NOEXIST);
    }
  } else {
    /* update/delete flow state in the map */
    // bpf_printk("token_map hit");
    bpf_spin_lock(&token->lock);
    u32 token_increase = (cur_time - token->last_time) >> TOKEN_RATE;
    // bpf_printk("token_increase: %ld\n", token_increase);
    u32 token_new = token->num + token_increase;
    u32 token_remain = 0;
    if (token_new > MAX_TOKEN) {
      token_new = MAX_TOKEN;
    }
    if (token_new < token_needed) {
      rc = XDP_DROP;
      token_remain = token_new;
    } else {
      rc = XDP_PASS;
      token_remain = token_new - token_needed;
    }
    token->num = token_remain;
    token->last_time = cur_time;
    bpf_spin_unlock(&token->lock);
    if (remove_session_table) {
      // bpf_printk("token_map remove");
      bpf_map_delete_elem(&token_map, &flow);
    }
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
