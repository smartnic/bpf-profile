/*
 * packet/flow number counter
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct cpu_counter {
  u32 packets;
  u32 flows;
} __attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct cpu_counter);
  __uint(max_entries, 1);
} my_map SEC(".maps");

SEC("xdpex1")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  struct iphdr *iph;
  struct cpu_counter *counter;
  u16 h_proto;
  u64 nh_off;
  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_DROP;

  h_proto = eth->h_proto;
  if (h_proto != htons(ETH_P_IP)) {
    return XDP_DROP;
  }

  iph = data + nh_off;
  if (iph + 1 > data_end)
    return XDP_DROP;
  nh_off += sizeof(*iph);
  bool new_flow = false;
  if (iph->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = data + nh_off;
    if (tcp + 1 > data_end)
      return XDP_DROP;
    new_flow = tcp->fin;
  }
  int index = 0;
  counter = bpf_map_lookup_elem(&my_map, &index);
  if (counter) {
    counter->packets++;
    // bpf_printk("value=%u", *value);
    if (new_flow) {
      counter->flows++;
    }
  } else {
    // bpf_printk("value==null");
  }
  return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
