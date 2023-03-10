/*
 * Copyright 2018 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/* Shared-nothing, full headers in metadata */
#define SRC_MATCH 1
#define DST_MATCH 0

#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <bpf/bpf_helpers.h>
#include "xdp_utils.h"

/* size: 46 bytes */
struct metadata_elem {
  struct ethhdr eth; /* 14 bytes */
  struct iphdr ip;   /* 20 bytes */
  struct udphdr udp; /* 8 bytes */
  u32 pkt_size;      /* 4 bytes */
} __attribute__((packed));

/*
 * dropcount is used to store dropped pkts counters.
 * key (uint32_t): [0] always stored at same array position
 * value (u64): pkts counter.
 */
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, int);
  __type(value, u64);
  __uint(max_entries, 1);
} dropcnt SEC(".maps");
// BPF_TABLE("percpu_array", int, u64, dropcnt, 1);

/*
 * srcblocklist is used to lookup and filter pkts using ipv4 src addresses.
 * key (uint32_t): ipv4 address.
 * value (u64): used for matched rules counters.
 */
#if SRC_MATCH
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, uint32_t);
  __type(value, u64);
  __uint(max_entries, 1024);
} srcblocklist SEC(".maps");
// BPF_TABLE("percpu_hash", uint32_t, u64, srcblocklist, 1024);
// TODO it should be u64 as value
#endif

/*
 * dstblocklist is used to lookup and filter pkts using ipv4 dst addresses.
 * key (uint32_t): ipv4 address.
 * value (u64): used for matched rules counters.
 */
#if DST_MATCH
struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
  __type(key, uint32_t);
  __type(value, u64);
  __uint(max_entries, 1024);
} dstblocklist SEC(".maps");
// BPF_TABLE("percpu_hash", uint32_t, u64, dstblocklist, 1024);
// TODO it should be u64 as value
#endif

/*
 * This function is called each time a packet arrives to the cube.
 * ctx contains the packet and md some additional metadata for the packet.
 * If the service is of type XDP_SKB/DRV CTXTYPE is equivalent to the struct
 * xdp_md
 * otherwise, if the service is of type TC, CTXTYPE is equivalent to the
 * __sk_buff struct
 * Please look at the libpolycube documentation for more details.
 */
static inline int parse_ipv4(void *data, u64 nh_off, void *data_end) {
  struct iphdr *iph = data + nh_off;

  if ((void *)&iph[1] > data_end)
    return 0;

#if SRC_MATCH
  /* Zero out the least significant 3 bits as they are used for RSS (note: src_ip is be32) */
  uint32_t src = iph->saddr & 0xf8ffffff;

  u64 *cntsrc = bpf_map_lookup_elem(&srcblocklist, &src);
  if (cntsrc) {
    *cntsrc += 1;
    return iph->protocol;
  }

#endif

#if DST_MATCH
  uint32_t dst = iph->daddr & 0xf8ffffff;

  u64 cntdst = bpf_map_lookup_elem(&dstblocklist, &dst);
  if (cntdst) {
    *cntdst += 1;
    return iph->protocol;
  }

#endif

  return 0;
}

static inline int parse_ipv4_metadata(uint32_t saddr, uint32_t daddr) {

#if SRC_MATCH
  /* Zero out the least significant 3 bits as they are used for RSS (note: src_ip is be32) */
  uint32_t src = saddr & 0xf8ffffff;

  u64 *cntsrc = bpf_map_lookup_elem(&srcblocklist, &src);
  if (cntsrc) {
    *cntsrc += 1;
    return 1;
  }

#endif

#if DST_MATCH
  uint32_t dst = daddr & 0xf8ffffff;

  u64 cntdst = bpf_map_lookup_elem(&dstblocklist, &dst);
  if (cntdst) {
    *cntdst += 1;
    return 1;
  }

#endif

  return 0;
}

SEC("xdp_ddos_mitigator")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  uint64_t offset = 0;
  int result = 0;
  uint16_t ethtype;
  u64 *value;

  /* Process the previous packets using metadata */
  struct metadata_elem* md;
  void* md_start = data;
  u64 md_size = (NUM_PKTS - 1) * sizeof(struct metadata_elem);
  /* safety check of accessing metadata */
  if (md_start + md_size > data_end) {
    return XDP_DROP;
  }
  u32 index = 0;
  value = bpf_map_lookup_elem(&dropcnt, &index);
  if (!value) {
    return XDP_DROP;
  }
  /* read metadata element */
  for (int i = 0; i < NUM_PKTS - 1; i++) {
    md = md_start + i * sizeof(struct metadata_elem);
    result = 0;
    ethtype = md->eth.h_proto;
    if (ethtype == htons(ETH_P_IP)) {
      result = parse_ipv4_metadata(md->ip.saddr, md->ip.daddr);
    }
    if (result != 0) {
      // bpf_printk("metadata %d hit\n", i);
      *value += 1;
    }
  }
  /* update the start address of the assigned packet */
  data = data + md_size;
  eth = data;
  result = 0;

  offset = sizeof(*eth);

  if (data + offset > data_end) {
    // goto PASS;
    return XDP_DROP;
  }

  ethtype = eth->h_proto;
  if (ethtype == htons(ETH_P_IP))
    result = parse_ipv4(data, offset, data_end);

  if (result != 0) {
    // bpf_printk("pkt hit\n");
    *value += 1;
  }

  data = (void *)(long)ctx->data;
  if (data + sizeof(struct ethhdr) > data_end) {
    return XDP_DROP;
  }
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
