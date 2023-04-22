/* rate limiting on each flow using token bucket (single token rate)
 * flow: 5 tuples
 * shared-nothing related fields, cuckoo hash
 */

#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include "lib/cuckoo_hash.h"
#include "xdp_utils.h"

#define MAX_NUM_FLOWS 1024
/* (1 >> TOKEN_RATE) packets per nanosecond */
#define TOKEN_RATE 10
#define MAX_TOKEN 16
#define RET_ERR -1

/* size: 13 bytes */
struct flow_key {
  u8 protocol;
  __be32 src_ip;
  __be32 dst_ip;
  u16 src_port;
  u16 dst_port;
} __attribute__((packed));

/* size: 23 bytes */
struct metadata_elem {
  __be16 ethtype;
  struct flow_key flow;
  u64 time;
} __attribute__((packed));

struct token_elem {
  u32 num;        /* number of tokens */
  u64 last_time;  /* flow's last arriving time */
} __attribute__((packed));

// map: key: flow;
// value: (1) # of tokens; (2) last time stamp
BPF_CUCKOO_HASH(token_map, struct flow_key, struct token_elem, MAX_NUM_FLOWS / 2)

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
  // bpf_printk("cur_time: %lld\n", cur_time);
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct token_elem *token = NULL;
  int rc = XDP_DROP;
  u32 token_needed = 1;

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
    md = md_start + i * sizeof(struct metadata_elem);
    md_flow = &md->flow;
    if (md->ethtype != htons(ETH_P_IP)) {
      continue;
    }
    if (md_flow->protocol != IPPROTO_UDP) {
      continue;
    }
    u64 time = md->time;
    md_flow->src_ip &= 0xf0ffffff;
    token = token_map_cuckoo_lookup(map, md_flow);
    if (!token) {
      /* set initial state */
      u32 token_remain = MAX_TOKEN - token_needed;
      struct token_elem elem;
      elem.num = token_remain;
      elem.last_time = time;
      token_map_cuckoo_insert(map, md_flow, &elem);
    } else {
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
    }
  }

  /* Process the current packet */
  struct ethhdr *eth;
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
  nh_off = dummy_header_size + md_size;
  eth = data + nh_off;

  nh_off += sizeof(*eth);
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
  /* Zero out the least significant 4 bits as they are
     used for RSS (note: src_ip is be32) */
  flow.src_ip = iph->saddr & 0xf0ffffff;
  flow.dst_ip = iph->daddr;

  /* Parse udp header to get src_port and dst_port */
  nh_off += sizeof(*iph);
  if (parse_udp(data, nh_off, data_end, &flow.src_port,
                &flow.dst_port) == RET_ERR) {
    return XDP_DROP;
  }
  nh_off += sizeof(struct udphdr);

  token = token_map_cuckoo_lookup(map, &flow);
  if (!token) {
    /* configure flow initial state in the map */
    rc = XDP_PASS;
    u32 token_remain = MAX_TOKEN - token_needed;
    struct token_elem elem;
    elem.num = token_remain;
    elem.last_time = cur_time;
    token_map_cuckoo_insert(map, &flow, &elem);
  } else {
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
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
