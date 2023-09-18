/* rate limiting on each flow using token bucket (single token rate)
 * flow: 5 tuples
 * shared-nothing related fields, cuckoo hash, compressed md, tcp
 */

#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include "lib/cuckoo_hash.h"
#include "xdp_utils.h"

#define MAX_NUM_FLOWS 1024
/* (1 >> TOKEN_RATE) packets per nanosecond */
#define TOKEN_RATE 10
#define MAX_TOKEN 16
#define RET_ERR -1

/* size: 12 bytes */
struct flow_key {
  __be32 src_ip;
  __be32 dst_ip;
  u16 src_port;
  u16 dst_port;
} __attribute__((packed));

/* size: 23 bytes */
struct metadata_elem {
  struct flow_key flow;
  u32 time;
  bool tcp_syn_flag;
  bool tcp_fin_flag; /* if true: is a tcp fin packet */
} __attribute__((packed));

struct token_elem {
  u32 num;        /* number of tokens */
  u32 last_time;  /* flow's last arriving time */
} __attribute__((packed));

// map: key: flow;
// value: (1) # of tokens; (2) last time stamp
BPF_CUCKOO_HASH(token_map, struct flow_key, struct token_elem, MAX_NUM_FLOWS / 2)

SEC("xdp")
int xdp_prog(struct xdp_md* ctx) {
  u32 cur_time = bpf_ktime_get_ns();
  // bpf_printk("cur_time: %lld\n", cur_time);
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct token_elem *token = NULL;
  int rc = XDP_DROP;
  u32 token_needed = 1;
  bool need_session_table = false;
  bool remove_session_table = false;

  uint32_t zero = 0;
  struct token_map_cuckoo_hash_map *map = bpf_map_lookup_elem(&token_map, &zero);
  if (!map) {
    // bpf_printk("map not found");
    return XDP_DROP;
  }

  /* Process previous packets using metadata */
  struct metadata_elem* md;
  struct flow_key *md_flow;
  int dummy_header_size = sizeof(struct ethhdr);
  int md_offset = dummy_header_size;
  void* md_start = data + md_offset;
  u64 md_size = (NUM_PKTS - 1) * sizeof(struct metadata_elem);
  /* safety check of accessing metadata */
  if (md_start + md_size > data_end) {
    return XDP_DROP;
  }
  /* process each packet */
  for (int i = 0; i < NUM_PKTS - 1; i++) {
    // bpf_printk("process packet %d", i);
    md = md_start + i * sizeof(struct metadata_elem);
    md_flow = &md->flow;
    need_session_table = md->tcp_syn_flag;
    remove_session_table = md->tcp_fin_flag;
    u32 time = md->time;
    token = token_map_cuckoo_lookup(map, md_flow);
    // bpf_printk("%d, %04x:%d -> %04x:%d", md_flow->protocol,
    //            md_flow->src_ip, md_flow->src_port,
    //            md_flow->dst_ip, md_flow->dst_port);
    if (!token) {
      // bpf_printk("token_map miss");
      if (need_session_table) {
        /* set initial state */
        u32 token_remain = MAX_TOKEN - token_needed;
        struct token_elem elem;
        elem.num = token_remain;
        elem.last_time = time;
        // bpf_printk("token_map insert");
        token_map_cuckoo_insert(map, md_flow, &elem);
      }
    } else {
      // bpf_printk("token_map hit");
      /* update flow state in the map */
      // bpf_printk("%d last time: %lld, time: %lld\n", i, token->last_time, token->last_time);
      u32 token_increase = (time - token->last_time) >> TOKEN_RATE;
      // bpf_printk("%d token_increase: %ld\n", i, token_increase);
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
      token->last_time = time;
      if (remove_session_table) {
        // bpf_printk("token_map remove");
        token_map_cuckoo_delete(map, md_flow);
      }
    }
  }

  /* Process the current packet */
  struct ethhdr *eth;
  struct iphdr *iph;
  struct flow_key flow = {
    .src_ip = 0,
    .dst_ip = 0,
    .src_port = 0,
    .dst_port = 0
  };
  u16 h_proto;
  u64 nh_off;
  nh_off = dummy_header_size + md_size;
  eth = data + nh_off;
  remove_session_table = false;

  nh_off += sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_DROP;

  h_proto = eth->h_proto;
  if (h_proto != htons(ETH_P_IP)) {
    return XDP_DROP;
  }
  /* Parse ipv4 header to get src_ip, and dst_ip */
  iph = data + nh_off;
  if (iph + 1 > data_end)
    return XDP_DROP;

  /* Zero out the least significant 4 bits as they are
     used for RSS (note: src_ip is be32) */
  flow.src_ip = iph->saddr;
  flow.dst_ip = iph->daddr;

  nh_off += sizeof(*iph);
  if (iph->protocol == IPPROTO_TCP) {
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
    /* drop packets that are not tcp */
    return XDP_DROP;
  }
  // bpf_printk("%d, %04x:%d -> %04x:%d", flow.protocol,
  //            flow.src_ip, flow.src_port,
  //            flow.dst_ip, flow.dst_port);
  token = token_map_cuckoo_lookup(map, &flow);
  if (!token) {
    // bpf_printk("token_map miss");
    /* configure flow initial state in the map */
    rc = XDP_PASS;
    if (need_session_table) {
      u32 token_remain = MAX_TOKEN - token_needed;
      struct token_elem elem;
      elem.num = token_remain;
      elem.last_time = cur_time;
      // bpf_printk("token_map insert");
      token_map_cuckoo_insert(map, &flow, &elem);
    }
  } else {
    // bpf_printk("token_map hit");
    /* update flow state in the map */
    // bpf_printk("last time: %lld\n", token->last_time);
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
    if (remove_session_table) {
      // bpf_printk("token_map remove");
      token_map_cuckoo_delete(map, &flow);
    }
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
