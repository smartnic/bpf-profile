/*
 * packet length counter
 */
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);
  __type(value, long);
  __uint(max_entries, 1024);
} my_map SEC(".maps");

SEC("xdpex1")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  long *value;
  u16 h_proto;
  u64 nh_off;

  nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_DROP;

  h_proto = eth->h_proto;
  if (h_proto != htons(ETH_P_IP)) {
    return XDP_DROP;
  }
  int index = 1;
  value = bpf_map_lookup_elem(&my_map, &index);
  if (value) {
    u64 bytes = data_end - data; /* Calculate packet length */
    __sync_fetch_and_add(value, bytes);
  }
  return XDP_DROP;
}

char _license[] SEC("license") = "GPL";
