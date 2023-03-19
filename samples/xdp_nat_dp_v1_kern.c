#define KBUILD_MODNAME "foo"
#include "xdp_nat_dp_common.h"
#include "xdp_utils.h"

#define NATTYPE NATTYPE_EGRESS

// session table also used by egrees programs
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct st_k);
  __type(value, struct st_v);
  __uint(max_entries, NAT_MAP_DIM);
} egress_session_table SEC(".maps");
struct {
  __uint(type, BPF_MAP_TYPE_LRU_HASH);
  __type(key, struct st_k);
  __type(value, struct st_v);
  __uint(max_entries, NAT_MAP_DIM);
} ingress_session_table SEC(".maps");

// BPF_TABLE_SHARED("lru_hash", struct st_k, struct st_v, egress_session_table,
//                  NAT_MAP_DIM);
// BPF_TABLE_SHARED("lru_hash", struct st_k, struct st_v, ingress_session_table,
//                  NAT_MAP_DIM);

// only needed in ingress
// DNAT + PORTFORWARDING rules
struct dp_k {
  u32 mask;
  __be32 external_ip;
  __be16 external_port;
  uint8_t proto;
};
struct dp_v {
  __be32 internal_ip;
  __be16 internal_port;
  uint8_t entry_type;
};
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct dp_k);
  __type(value, struct dp_v);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} dp_rules SEC(".maps");
// BPF_F_TABLE("lpm_trie", struct dp_k, struct dp_v, dp_rules, 1024,
//             BPF_F_NO_PREALLOC);


// only needed in egress
// SNAT + MASQUERADE rules
struct sm_k {
  u32 internal_netmask_len;
  __be32 internal_ip;
};
struct sm_v {
  __be32 external_ip;
  uint8_t entry_type;
};
struct {
  __uint(type, BPF_MAP_TYPE_LPM_TRIE);
  __type(key, struct sm_k);
  __type(value, struct sm_v);
  __uint(max_entries, 1024);
  __uint(map_flags, BPF_F_NO_PREALLOC);
} sm_rules SEC(".maps");
// BPF_F_TABLE("lpm_trie", struct sm_k, struct sm_v, sm_rules, 1024,
//             BPF_F_NO_PREALLOC);
// Port numbers
struct free_port_entry {
  u16 first_free_port;
  struct bpf_spin_lock lock;
};
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, struct free_port_entry);
  __uint(max_entries, 1);
} first_free_port SEC(".maps");
// BPF_TABLE("array", u32, struct free_port_entry, first_free_port, 1);
static inline __be16 get_free_port() {
  u32 i = 0;
  u16 port = 0;
  struct free_port_entry *entry = bpf_map_lookup_elem(&first_free_port, &i);
  if (!entry)
    return 0;
  bpf_spin_lock(&entry->lock);
  if (entry->first_free_port < 1024 || entry->first_free_port == 65535)
    entry->first_free_port = 1024;
  port = entry->first_free_port;
  entry->first_free_port++;
  bpf_spin_unlock(&entry->lock);
  return htons(port);
}

SEC("xdp_nat_dp")
int xdp_prog(struct xdp_md *ctx) {
  // NAT processing happens in 4 steps:
  // 1) packet parsing
  // 2) session table lookup
  // 3) rule lookup
  // 4) packet modification

  // Parse packet
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct eth_hdr *eth = data;
  if ( (void *)eth + sizeof(*eth) > data_end )
    goto DROP;

  bpf_printk("Received new packet. eth_type: 0x%x mac_src: %M mac_dst: %M",
             ntohs(eth->proto), eth->src, eth->dst);

  switch (eth->proto) {
  case htons(ETH_P_IP):
    // Packet is IP
    bpf_printk("Received IP Packet");
    break;
  case htons(ETH_P_ARP):
    // Packet is ARP: let is pass
    bpf_printk("Received ARP packet. Letting it go through");
    return RX_OK;
  default:
    bpf_printk("Unknown eth proto: %d, dropping",
               ntohs(eth->proto));
    goto DROP;
  }

  // Packet data
  uint32_t srcIp = 0;
  uint32_t dstIp = 0;
  uint16_t srcPort = 0;
  uint16_t dstPort = 0;
  uint8_t proto = 0;

  // Nat data
  uint32_t newIp = 0;
  uint16_t newPort = 0;
  uint8_t rule_type = 0;

  // Status data
  uint8_t update_session_table = 1;

  struct iphdr *ip = data + sizeof(*eth);
  if ( (void *)ip + sizeof(*ip) > data_end )
    goto DROP;

  bpf_printk("Processing IP packet: src %04x, dst: %04x", ntohl(ip->saddr),
             ntohl(ip->daddr));

  srcIp = ip->saddr;
  dstIp = ip->daddr;
  proto = ip->protocol;

  switch (ip->protocol) {
  case IPPROTO_TCP: {
    uint8_t header_len = 4 * ip->ihl;
    // uint8_t header_len = sizeof(*ip);
    struct tcphdr *tcp = data + sizeof(*eth) + header_len;
    if ( (void *)tcp + sizeof(*tcp) > data_end )
      goto DROP;

    bpf_printk("Packet is TCP: src_port %d, dst_port %d",
               tcp->source, tcp->dest);
    srcPort = tcp->source;
    dstPort = tcp->dest;
    break;
  }
  case IPPROTO_UDP: {
    uint8_t header_len = 4 * ip->ihl;
    // uint8_t header_len = sizeof(*ip);
    struct udphdr *udp = data + sizeof(*eth) + header_len;
    if ( (void *)udp + sizeof(*udp) > data_end )
      goto DROP;
    bpf_printk("Packet is UDP: src_port %d, dst_port %d",
               ntohs(udp->source), ntohs(udp->dest));
    srcPort = udp->source;
    dstPort = udp->dest;
    break;
  }
  case IPPROTO_ICMP: {
    uint8_t header_len = 4 * ip->ihl;
    // uint8_t header_len = sizeof(*ip);
    struct icmphdr *icmp = data + sizeof(*eth) + header_len;
    if ( (void *)icmp + sizeof(*icmp) > data_end )
      goto DROP;
    bpf_printk("Packet is ICMP: type %d, id %d", icmp->type,
               icmp->un.echo.id);

    // Consider the ICMP ID as a "port" number for easier handling
    srcPort = icmp->un.echo.id;
    dstPort = icmp->un.echo.id;
    break;
  }
  default:
    bpf_printk("Unknown L4 proto %d, dropping", ip->protocol);
    goto DROP;
  }

  // Packet parsed, start session table lookup
  struct st_k key = {0, 0, 0, 0, 0};
  key.src_ip = srcIp;
  key.dst_ip = dstIp;
  key.src_port = srcPort;
  key.dst_port = dstPort;
  key.proto = proto;
  struct st_v *value;

#if NATTYPE == NATTYPE_EGRESS
  // Packet is inside -> outside, check egress session table
  value = bpf_map_lookup_elem(&egress_session_table, &key);
  if (value != NULL) {
    // Session table hit
    bpf_printk("Egress session table: hit");

    newIp = value->new_ip;
    newPort = value->new_port;
    rule_type = NAT_SRC;

    update_session_table = 0;

    goto apply_nat;
  }
  bpf_printk("Egress session table: miss");
//  } else {
#elif NATTYPE == NATTYPE_INGRESS
  // Packet is outside -> inside, check ingress session table
  value = bpf_map_lookup_elem(&ingress_session_table, &key);
  if (value != NULL) {
    // Session table hit
    bpf_printk("Ingress session table: hit");

    newIp = value->new_ip;
    newPort = value->new_port;
    rule_type = NAT_DST;

    update_session_table = 0;

    goto apply_nat;
  }
  bpf_printk("Ingress session table: miss");
//  }
#else
#error "Invalid NATTYPE"
#endif
// Session table miss, start rule lookup

#if NATTYPE == NATTYPE_EGRESS
  {
    // Packet is inside -> outside, check SNAT/MASQUERADE rule table
    struct sm_k key = {0, 0};
    key.internal_netmask_len = 32;
    key.internal_ip = srcIp;
    struct sm_v *value = bpf_map_lookup_elem(&sm_rules, &key);
    if (value != NULL) {
      bpf_printk("Egress rule table: hit");

      newIp = value->external_ip;
      newPort = get_free_port();
      rule_type = value->entry_type;

      goto apply_nat;
    }
    bpf_printk("Egress rule table: miss");
  }
//  } else {
#elif NATTYPE == NATTYPE_INGRESS
  // Packet is outside -> inside, check DNAT/PORTFORWARDING rule table
  {
    struct dp_k key = {0, 0, 0};
    key.mask = 56;  // 32 (IP) + 16 (Port) + 8 (Proto)
    key.external_ip = dstIp;
    key.external_port = dstPort;
    key.proto = proto;
    struct dp_v *value = bpf_map_lookup_elem(&dp_rules, &key);
    if (value != NULL) {
      bpf_printk("Ingress rule table: hit");

      newIp = value->internal_ip;
      newPort = value->internal_port;
      rule_type = value->entry_type;
      if (newPort == 0) {
        // Matching rule is DNAT, keep the same port number
        newPort = dstPort;
      }

      goto apply_nat;
    }
    bpf_printk("Ingress rule table: miss");
  }
//  }
#else
#error "Invalid NATTYPE"
#endif
  // No matching entry was found in the session tables
  // No matching rule was found in the rule tables
  // -> Forward packet as it is
  goto proceed;

apply_nat:;
  if (update_session_table == 1) {
    // No session table exist for the packet, but a rule matched
    // -> Update the session tables in both directions

    struct st_k forward_key = {0, 0, 0, 0, 0};
    struct st_v forward_value = {0, 0};

    struct st_k reverse_key = {0, 0, 0, 0, 0};
    struct st_v reverse_value = {0, 0};

    if (rule_type == NAT_SRC || rule_type == NAT_MSQ) {
      // A rule matched in the inside -> outside direction

      // Session table entry for the outgoing packets
      forward_key.src_ip = srcIp;
      forward_key.dst_ip = dstIp;
      forward_key.src_port = srcPort;
      forward_key.dst_port = dstPort;
      forward_key.proto = proto;

      forward_value.new_ip = newIp;
      forward_value.new_port = newPort;
      forward_value.originating_rule_type = rule_type;

      // Session table entry for the incoming packets
      reverse_key.src_ip = dstIp;
      reverse_key.dst_ip = newIp;
      if (proto == IPPROTO_ICMP) {
        // For ICMP session table entries "source port" and "destination port"
        // must be the same, equal to the ICMP ID
        reverse_key.src_port = newPort;
      } else {
        reverse_key.src_port = dstPort;
      }
      reverse_key.dst_port = newPort;
      reverse_key.proto = proto;

      reverse_value.new_ip = srcIp;
      reverse_value.new_port = srcPort;
      reverse_value.originating_rule_type = rule_type;

      bpf_printk("Updating session tables after SNAT");
      bpf_printk("New outgoing connection: %04x:%d -> %04x:%d", ntohl(srcIp),
                 ntohs(srcPort), ntohl(dstIp), ntohs(dstPort));
    } else {
      // A rule matched in the outside -> inside direction

      // Session table entry for the outgoing packets
      forward_key.src_ip = newIp;
      forward_key.dst_ip = srcIp;
      forward_key.src_port = newPort;
      if (proto == IPPROTO_ICMP) {
        // For ICMP session table entries "source port" and "destination port"
        // must be the same, equal to the ICMP ID
        forward_key.dst_port = newPort;
      } else {
        forward_key.dst_port = srcPort;
      }
      forward_key.proto = proto;

      forward_value.new_ip = dstIp;
      forward_value.new_port = dstPort;
      forward_value.originating_rule_type = rule_type;

      // Session table entry for the incoming packets
      reverse_key.src_ip = srcIp;
      reverse_key.dst_ip = dstIp;
      reverse_key.src_port = srcPort;
      reverse_key.dst_port = dstPort;
      reverse_key.proto = proto;

      reverse_value.new_ip = newIp;
      reverse_value.new_port = newPort;
      reverse_value.originating_rule_type = rule_type;

      bpf_printk("Updating session tables after DNAT");
      bpf_printk("New incoming connection: %04x:%d -> %04x:%d", ntohl(srcIp),
                 srcPort, ntohl(dstIp), dstPort);
    }
    bpf_map_update_elem(&egress_session_table, &forward_key,
                        &forward_value, BPF_NOEXIST);
    bpf_map_update_elem(&ingress_session_table, &reverse_key,
                        &reverse_value, BPF_NOEXIST);
    bpf_printk("Using ingress key: srcIp %04x, dstIp %04x, srcPort %d, dstPort %d",
               ntohl(reverse_key.src_ip), ntohl(reverse_key.dst_ip),
               ntohs(reverse_key.src_port), ntohs(reverse_key.dst_port));
    bpf_printk("Using egress key: srcIp %04x, dstIp %04x, srcPort %d, dstPort %d",
               ntohl(forward_key.src_ip), ntohl(forward_key.dst_ip),
               ntohs(forward_key.src_port), ntohs(forward_key.dst_port));
  }

  // Modify packet
  uint32_t old_ip =
    (rule_type == NAT_SRC || rule_type == NAT_MSQ) ? srcIp : dstIp;
  uint32_t old_port =
    (rule_type == NAT_SRC || rule_type == NAT_MSQ) ? srcPort : dstPort;
  uint32_t new_ip = newIp;
  uint32_t new_port = newPort;
  uint32_t l3sum = bpf_csum_diff(&old_ip, 4, &new_ip, 4, 0);
  uint32_t l4sum = bpf_csum_diff(&old_port, 4, &new_port, 4, 0);
  switch (proto) {
  case IPPROTO_TCP: {
    uint8_t header_len = 4 * ip->ihl;
    // uint8_t header_len = sizeof(*ip);
    struct tcphdr *tcp = data + sizeof(*eth) + header_len;
    if ( (void *)tcp + sizeof(*tcp) > data_end )
      goto DROP;

    if (rule_type == NAT_SRC || rule_type == NAT_MSQ) {
      ip->saddr = new_ip;
      tcp->source = (__be16)new_port;
      bpf_printk("Natted TCP packet: source, %04x:%d -> %04x:%d",
                 ntohl(old_ip), ntohs(old_port), ntohl(new_ip), ntohs(new_port));
    } else {
      ip->daddr = new_ip;
      tcp->dest = (__be16)new_port;
      bpf_printk("Natted TCP packet: destination, %04x:%d -> %04x:%d",
                 ntohl(old_ip), ntohs(old_port), ntohl(new_ip), ntohs(new_port));
    }

    // Update checksums
    pcn_l4_csum_replace(ctx, TCP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
    pcn_l4_csum_replace(ctx, TCP_CSUM_OFFSET, 0, l4sum, 0);
    pcn_l3_csum_replace(ctx, IP_CSUM_OFFSET, 0, l3sum, 0);

    goto proceed;
  }
  case IPPROTO_UDP: {
    uint8_t header_len = 4 * ip->ihl;
    // uint8_t header_len = sizeof(*ip);
    struct udphdr *udp = data + sizeof(*eth) + header_len;
    if ( (void *)udp + sizeof(*udp) > data_end )
      goto DROP;
    if (rule_type == NAT_SRC || rule_type == NAT_MSQ) {
      ip->saddr = new_ip;
      udp->source = (__be16)new_port;
      bpf_printk("Natted UDP packet: source, %04x:%d -> %04x:%d",
                 ntohl(old_ip), ntohs(old_port), ntohl(new_ip), ntohs(new_port));
    } else {
      ip->daddr = new_ip;
      udp->dest = (__be16)new_port;
      bpf_printk("Natted UDP packet: destination, %04x:%d -> %04x:%d",
                 ntohl(old_ip), ntohs(old_port), ntohl(new_ip), ntohs(new_port));
    }

    // Update checksums
    pcn_l4_csum_replace(ctx, UDP_CSUM_OFFSET, 0, l3sum, IS_PSEUDO | 0);
    pcn_l4_csum_replace(ctx, UDP_CSUM_OFFSET, 0, l4sum, 0);
    pcn_l3_csum_replace(ctx, IP_CSUM_OFFSET, 0, l3sum, 0);

    goto proceed;
  }
  case IPPROTO_ICMP: {
    uint8_t header_len = 4 * ip->ihl;
    // uint8_t header_len = sizeof(*ip);
    struct icmphdr *icmp = data + sizeof(*eth) + header_len;
    if ( (void *)icmp + sizeof(*icmp) > data_end )
      goto DROP;
    if (rule_type == NAT_SRC || rule_type == NAT_MSQ) {
      ip->saddr = new_ip;
      icmp->un.echo.id = (__be16)new_port;
      bpf_printk("Natted ICMP packet: source, %04x:%d -> %04x:%d",
                 ntohl(old_ip), ntohs(old_port), ntohl(new_ip), ntohs(new_port));
    } else {
      ip->daddr = new_ip;
      icmp->un.echo.id = (__be16)new_port;
      bpf_printk("Natted ICMP packet: destination, %04x:%d -> %04x:%d",
                 ntohl(old_ip), ntohs(old_port), ntohl(new_ip), ntohs(new_port));
    }

    // Update checksums
    pcn_l4_csum_replace(ctx, ICMP_CSUM_OFFSET, 0, l4sum, 0);
    pcn_l3_csum_replace(ctx, IP_CSUM_OFFSET, 0, l3sum, 0);

    goto proceed;
  }
  }
proceed:;
  /* todo: bounce packets back */
  // return RX_OK;
  swap_src_dst_mac(data);
  return XDP_TX;
DROP:;
  bpf_printk("Dropping packet");
  return RX_DROP;
}

char _license[] SEC("license") = "GPL";