/*
 * A dump xdp program
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include "xdp_utils.h"

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, u32);   /* dummy key */
  __type(value, u32); /* # of iterations in the loop */
  __uint(max_entries, 1);
} map SEC(".maps");

static inline int loop1(__u32 index, void *data) {
  return 0;
}

static inline void compute(u32 num_iters) {
  bpf_loop(num_iters, loop1, NULL, 0);
}

SEC("xdp_compute")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_DROP;

  u32 zero = 0;
  u32 *num_iters = bpf_map_lookup_elem(&map, &zero);
  if (!num_iters) {
    return XDP_DROP;
  }

  for (int i = 0; i < NUM_PKTS; i++) {
    compute(*num_iters);
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
