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

/* shared state (atomic) */
#define SRC_MATCH 1
#define DST_MATCH 0

#define KBUILD_MODNAME "foo"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <stddef.h>
#include <stdint.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "xdp_utils.h"

/*
 * dropcount is used to store dropped pkts counters.
 * key (uint32_t): [0] always stored at same array position
 * value (__u64): pkts counter.
 */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, int);
  __type(value, __u64);
  __uint(max_entries, 1);
} dropcnt SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, __u32);
    __type(value, __u64);
    __uint(max_entries, 512);
} count_map SEC(".maps");
// BPF_TABLE("percpu_array", int, __u64, dropcnt, 1);

/*
 * srcblocklist is used to lookup and filter pkts using ipv4 src addresses.
 * key (uint32_t): ipv4 address.
 * value (__u64): used for matched rules counters.
 */
#if SRC_MATCH
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, uint32_t);
  __type(value, __u64);
  __uint(max_entries, 1024);
} srcblocklist SEC(".maps");
// BPF_TABLE("percpu_hash", uint32_t, __u64, srcblocklist, 1024);
// TODO it should be __u64 as value
#endif

/*
 * dstblocklist is used to lookup and filter pkts using ipv4 dst addresses.
 * key (uint32_t): ipv4 address.
 * value (__u64): used for matched rules counters.
 */
#if DST_MATCH
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, uint32_t);
  __type(value, __u64);
  __uint(max_entries, 1024);
} dstblocklist SEC(".maps");
// BPF_TABLE("percpu_hash", uint32_t, __u64, dstblocklist, 1024);
// TODO it should be __u64 as value
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
static inline int parse_ipv4(void *data, __u64 nh_off, void *data_end) {
  struct iphdr *iph = data + nh_off;

  if ((void *)&iph[1] > data_end)
    return 0;

#if SRC_MATCH
  uint32_t src = iph->saddr;

  // bpf_printk("src: %04x\n", src);
  __u64 *cntsrc = bpf_map_lookup_elem(&srcblocklist, &src);
  if (cntsrc) {
    __sync_fetch_and_add(cntsrc, 1);
    return iph->protocol;
  }

#endif

#if DST_MATCH
  uint32_t dst = iph->daddr;

  __u64 cntdst = bpf_map_lookup_elem(&dstblocklist, &dst);
  if (cntdst) {
    __sync_fetch_and_add(cntdst, 1);
    return iph->protocol;
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
  __u64 *value;

  offset = sizeof(*eth);

  if (data + offset > data_end) {
    // goto PASS;
    return XDP_DROP;
  }

  /* RSS++ section start */
  __u64 *count_map_value;

  __u32 hash_id = ctx->hash % 256; //TODO : change according to the current number of queue. But the map size would need to be changed too. Therefore it would be more practical to simply recompile this file with a different parameter.

  count_map_value = bpf_map_lookup_elem(&count_map, &hash_id);
  if (count_map_value)
      __sync_fetch_and_add(count_map_value, 1);
  
  /* RSS++ section end */

  ethtype = eth->h_proto;
  if (ethtype == bpf_htons(ETH_P_IP))
    result = parse_ipv4(data, offset, data_end);

  if (result == 0) {
    // goto PASS;
    swap_src_dst_mac(data);
    return XDP_TX;
  }

  __u32 index = 0;
  value = bpf_map_lookup_elem(&dropcnt, &index);
  if (value) {
    __sync_fetch_and_add(value, 1);
    // pcn_log(ctx, LOG_DEBUG, "Dropcount proto:%d value: %d ", result, *value);
  }

  // pcn_log(ctx, LOG_DEBUG, "Dropping packet ethtype: %x ", eth->h_proto);
  // return XDP_DROP;
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
