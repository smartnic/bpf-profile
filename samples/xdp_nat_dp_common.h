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

// TODO: comment
#define RX_OK XDP_PASS
#define RX_DROP XDP_DROP
#define NAT_SRC 1
#define NAT_DST 2
#define NAT_MSQ 3
#define NAT_PFW 4
#define NATTYPE_INGRESS 1
#define NATTYPE_EGRESS 2
#include <uapi/linux/bpf.h>
#include <linux/filter.h>
#include <linux/icmp.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#define NAT_MAP_DIM 32768
#define IP_CSUM_OFFSET (sizeof(struct eth_hdr) + offsetof(struct iphdr, check))
#define UDP_CSUM_OFFSET                            \
  (sizeof(struct eth_hdr) + sizeof(struct iphdr) + \
   offsetof(struct udphdr, check))
#define TCP_CSUM_OFFSET                            \
  (sizeof(struct eth_hdr) + sizeof(struct iphdr) + \
   offsetof(struct tcphdr, check))
#define ICMP_CSUM_OFFSET                           \
  (sizeof(struct eth_hdr) + sizeof(struct iphdr) + \
   offsetof(struct icmphdr, checksum))
#define IS_PSEUDO 0x10

/* __attribute__((packed))
 * forces alignment for this structure;
 * otherwise misaligned read/write could happen
 * between userspace and kernel space.
 * same attribute should be used in kernel/user space
 * structs declaration.
 */
struct eth_hdr {
  __be64 dst : 48;
  __be64 src : 48;
  __be16 proto;
} __attribute__((packed));
// Session table
struct st_k {
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t proto;
} __attribute__((packed));
struct st_v {
  uint32_t new_ip;
  uint16_t new_port;
  uint8_t originating_rule_type;
} __attribute__((packed));


/* checksum related stuff */
static __always_inline __sum16 pcn_csum_fold(__wsum csum) {
  u32 sum = (__force u32)csum;
  sum = (sum & 0xffff) + (sum >> 16);
  sum = (sum & 0xffff) + (sum >> 16);
  return (__force __sum16)~sum;
}

static __always_inline __wsum pcn_csum_unfold(__sum16 n) {
  return (__force __wsum)n;
}

static __always_inline __wsum pcn_csum_add(__wsum csum, __wsum addend) {
  u32 res = (__force u32)csum;
  res += (__force u32)addend;
  return (__force __wsum)(res + (res < (__force u32)addend));
}
static __always_inline __sum16 pcn_csum16_add(__sum16 csum, __be16 addend) {
  u16 res = (__force u16)csum;
  res += (__force u16)addend;
  return (__force __sum16)(res + (res < (__force u16)addend));
}

static __always_inline void pcn_csum_replace_by_diff(__sum16 *sum, __wsum diff) {
  *sum = pcn_csum_fold(pcn_csum_add(diff, ~pcn_csum_unfold(*sum)));
}

static __always_inline
int pcn_l3_csum_replace(struct xdp_md *ctx, u32 csum_offset,
                        u32 old_value, u32 new_value, u32 flags) {
  __sum16 *ptr;
  if (unlikely(flags & ~(BPF_F_HDR_FIELD_MASK)))
    return -EINVAL;
  if (unlikely(csum_offset > 0xffff || csum_offset & 1))
    return -EFAULT;
  void *data2 = (void*)(long)ctx->data;
  void *data_end2 = (void*)(long)ctx->data_end;
  if (data2 + csum_offset + sizeof(*ptr) > data_end2) {
    return -EINVAL;
  }
  ptr = (__sum16 *)((void*)(long)ctx->data + csum_offset);
  switch (flags & BPF_F_HDR_FIELD_MASK  ) {
  case 0:
    pcn_csum_replace_by_diff(ptr, new_value);
    break;
  case 2:
    *ptr = ~pcn_csum16_add(pcn_csum16_add(~(*ptr), ~old_value), new_value);
    break;
  case 4:
    pcn_csum_replace_by_diff(ptr, pcn_csum_add(new_value, ~old_value));
    break;
  default:
    return -EINVAL;
  }
  return 0;
}

static __always_inline
int pcn_l4_csum_replace(struct xdp_md *ctx, u32 csum_offset,
                        u32 old_value, u32 new_value, u32 flags) {
  bool is_pseudo = flags & BPF_F_PSEUDO_HDR;
  bool is_mmzero = flags & BPF_F_MARK_MANGLED_0;
  bool do_mforce = flags & BPF_F_MARK_ENFORCE;
  __sum16 *ptr;
  if (unlikely(flags & ~(BPF_F_MARK_MANGLED_0 | BPF_F_MARK_ENFORCE |
                         BPF_F_PSEUDO_HDR | BPF_F_HDR_FIELD_MASK)))
    return -EINVAL;
  if (unlikely(csum_offset > 0xffff || csum_offset & 1))
    return -EFAULT;
  void *data2 = (void*)(long)ctx->data;
  void *data_end2 = (void*)(long)ctx->data_end;
  if (data2 + csum_offset + sizeof(*ptr) > data_end2) {
    return -EINVAL;
  }
  ptr = (__sum16 *)((void*)(long)ctx->data + csum_offset);
  if (is_mmzero && !do_mforce && !*ptr)
    return 0;
  switch (flags & BPF_F_HDR_FIELD_MASK) {
  case 0:
    pcn_csum_replace_by_diff(ptr, new_value);
    break;
  case 2:
    *ptr = ~pcn_csum16_add(pcn_csum16_add(~(*ptr), ~old_value), new_value);
    break;
  case 4:
    pcn_csum_replace_by_diff(ptr, pcn_csum_add(new_value, ~old_value));
    break;
  default:
    return -EINVAL;
  }
  // It may happen that the checksum of UDP packets is 0;
  // in that case there is an ambiguity because 0 could be
  // considered as a packet without checksum, in that case
  // the checksum has to be "mangled" (i.e., write 0xffff instead of 0).
  if (is_mmzero && !*ptr)
    *ptr = CSUM_MANGLED_0;
  return 0;
}