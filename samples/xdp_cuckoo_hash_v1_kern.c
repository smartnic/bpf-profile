/*
 * An xdp program used to measure the performance of cuckoo hash lookup
 * 1 bpf lookup to find cuckoo hash
 * NUM_PKTS cuckoo hash lookup
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_helpers.h>
#include "lib/cuckoo_hash.h"
#include "xdp_utils.h"

BPF_CUCKOO_HASH(pktcnt, uint32_t, u64, 512)

SEC("xdp_cuckoo_hash")
int xdp_prog(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;
  u64 nh_off = sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_DROP;

  uint32_t index = 0;
  struct pktcnt_cuckoo_hash_map *pktcnt_ptr = bpf_map_lookup_elem(&pktcnt, &index);
  if (!pktcnt_ptr) {
    // bpf_printk("map not found");
    return XDP_DROP;
  }

  for (int i = 0; i < NUM_PKTS; i++) {
    uint32_t key = 0x12345678;
    u64 *value = pktcnt_cuckoo_lookup(pktcnt_ptr, &key);
    if (value) {
      *value += 1;
    } else {
      u64 zero = 0;
      pktcnt_cuckoo_insert(pktcnt_ptr, &key, &zero);
    }
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
