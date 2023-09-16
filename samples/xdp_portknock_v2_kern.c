/* portknocking using multiple cores, shared-nothing */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include "lib/cilium_builtin.h"
#include "lib/cuckoo_hash.h"
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

struct metadata_elem {
  u32 src_ip;
  u16 dst_port;      /* 4 bytes */
  bool tcp_syn_flag;
  bool tcp_fin_flag; /* if true: is a tcp fin packet */
} __attribute__((packed));

struct array_elem {
  u32 state;
};

BPF_CUCKOO_HASH(port_state_map, u32, struct array_elem, 512)

static inline u32 get_new_state(u32 state, u16 dst_port) {
  if (state == CLOSED_0 && dst_port == PORT_1) {
    state = CLOSED_1;
  } else if (state == CLOSED_1 && dst_port == PORT_2) {
    state = CLOSED_2;
  } else if (state == CLOSED_2 && dst_port == PORT_3) {
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
  struct iphdr *iph;
  u16 h_proto;
  u64 nh_off;
  int rc = XDP_DROP;
  bool need_session_table = false;
  bool remove_session_table = false;
  u16 dst_port;
  u32 src_ip;

  uint32_t zero = 0;
  struct port_state_map_cuckoo_hash_map *map = bpf_map_lookup_elem(&port_state_map, &zero);
  if (!map) {
    // bpf_printk("map not found");
    return XDP_DROP;
  }

  struct array_elem *port_state_ptr;
  /* Process latest (n-1) packets using metadata */
  int dummy_header_size = sizeof(struct ethhdr);
  int md_offset = dummy_header_size;
  void* md_start = data + md_offset;
  u64 md_size = (NUM_PKTS - 1) * sizeof(struct metadata_elem);
  if (md_start + md_size > data_end)
    return XDP_DROP;

  u32 curr_state;
  struct metadata_elem* md_elem;
  for (int i = 0; i < NUM_PKTS - 1; i++) {
    md_elem = md_start + i * sizeof(struct metadata_elem);
    need_session_table = md_elem->tcp_syn_flag;
    remove_session_table = md_elem->tcp_fin_flag;
    src_ip = md_elem->src_ip;
    dst_port = md_elem->dst_port;
    port_state_ptr = port_state_map_cuckoo_lookup(map, &src_ip);
    if (!port_state_ptr) {
      uint32_t new_state = CLOSED_0;
      if (dst_port == PORT_1) {
        new_state = CLOSED_1;
      }
      if (need_session_table) {
        struct array_elem elem;
        elem.state = new_state;
        port_state_map_cuckoo_insert(map, &src_ip, &elem);
      }
    } else {
      port_state_ptr->state = get_new_state(port_state_ptr->state, dst_port);
      if (remove_session_table) {
        port_state_map_cuckoo_delete(map, &src_ip);
      }
    }
  }

  /* Process the current packet */
  remove_session_table = false;
  need_session_table = false;
  nh_off = dummy_header_size + md_size;
  void* pkt_start = data + nh_off;
  struct ethhdr *eth = pkt_start;
  nh_off += sizeof(*eth);
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

  port_state_ptr = port_state_map_cuckoo_lookup(map, &src_ip);
  if (!port_state_ptr) {
    uint32_t new_state = CLOSED_0;
    if (dst_port == PORT_1) {
      new_state = CLOSED_1;
    }
    if (need_session_table) {
      struct array_elem elem;
      elem.state = new_state;
      port_state_map_cuckoo_insert(map, &src_ip, &elem);
    }
  } else {
    port_state_ptr->state = get_new_state(port_state_ptr->state, dst_port);
    if (port_state_ptr->state == OPEN) {
      rc = XDP_PASS;
    }
    if (remove_session_table) {
      port_state_map_cuckoo_delete(map, &src_ip);
    }
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";

