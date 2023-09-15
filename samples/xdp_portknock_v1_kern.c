/* portknocking using multiple cores, shared-state */
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

#define PORT_1 100
#define PORT_2 101
#define PORT_3 102

#define RET_ERR -1

struct array_elem {
  u32 state;
  struct bpf_spin_lock lock;
};

/*
 * key: src ip
 * value: state
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, u32);
  __type(value, struct array_elem);
  __uint(max_entries, 1024);
} port_state SEC(".maps");

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
  struct iphdr *iph;
  struct array_elem* value;
  u16 h_proto;
  u64 nh_off;
  int rc = XDP_DROP;
  bool need_session_table = false;
  bool remove_session_table = false;
  u16 dst_port;
  u32 src_ip;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_DROP;

  h_proto = eth->h_proto;
  if (h_proto != htons(ETH_P_IP)) {
    return XDP_DROP;
  }

  /* Parse ipv4 header to get protocol, src_ip */
  iph = data + nh_off;
  if (iph + 1 > data_end)
    return XDP_DROP;

  if (iph->protocol != IPPROTO_TCP) {
    return XDP_DROP;
  }
  src_ip = iph->saddr;

  nh_off += sizeof(*iph);
  /* Parse tcp header to get dst_port */
  struct tcphdr *tcp = data + nh_off;
  if (tcp + 1 > data_end)
    return XDP_DROP;
  dst_port = ntohs(tcp->dest);
  // check if entry needs to be removed
  remove_session_table = tcp->fin;
  // bpf_printk("fin_flag (remove entry): %s", remove_session_table ? "true" : "false");
  need_session_table = tcp->syn;

  value = bpf_map_lookup_elem(&port_state, &src_ip);
  if (!value) {
    uint32_t new_state = CLOSED_0;
    if (dst_port == PORT_1) {
      new_state = CLOSED_1;
    }
    if (need_session_table) {
      struct array_elem elem;
      __builtin_memset(&elem, 0, sizeof(elem));
      elem.state = new_state;
      bpf_map_update_elem(&port_state, &src_ip, &elem, BPF_NOEXIST);
    }
  } else {
    bpf_spin_lock(&value->lock);
    value->state = get_new_state(value->state, dst_port);
    if (value->state == OPEN) {
      rc = XDP_PASS;
    }
    bpf_spin_unlock(&value->lock);
    if (remove_session_table) {
      bpf_map_delete_elem(&port_state, &src_ip);
    }
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
