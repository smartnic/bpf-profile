/* portknocking using multiple cores, shared-nothing, support loss recovery
 * metadata log: compressed ring buffer
 */
#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include "lib/cilium_builtin.h"
#include "lib/cuckoo_hash.h"
#include "xdp_utils.h"
#include "bpf_log.h"

enum state {
  CLOSED_0 = 0,
  CLOSED_1,
  CLOSED_2,
  OPEN,
};

#define PORT_1 100
#define PORT_2 101
#define PORT_3 102

#define RET_ERR -1

struct metadata_elem {
  u32 src_ip;
  u16 dst_port;
  bool tcp_syn_flag;
  bool tcp_fin_flag; /* if true: is a tcp fin packet */
} __attribute__((packed));

struct array_elem {
  u32 state;
};

BPF_CUCKOO_HASH(port_state_map, u32, struct array_elem, 512)

static inline u32 get_new_state(u32 state, u16 dst_port) {
  if (state == CLOSED_0 && dst_port == PORT_1) {
    state = CLOSED_1;
  } else if (state == CLOSED_1 && dst_port == PORT_2) {
    state = CLOSED_2;
  } else if (state == CLOSED_2 && dst_port == PORT_3) {
    state = OPEN;
  } else {
    state = CLOSED_0;
  }
  return state;
}

static inline int update_state_by_metadata(struct metadata_elem *md_elem,
                                           struct port_state_map_cuckoo_hash_map *map) {
    bool need_session_table = md_elem->tcp_syn_flag;
    bool remove_session_table = md_elem->tcp_fin_flag;
    u32 src_ip = md_elem->src_ip;
    u16 dst_port = md_elem->dst_port;
    struct array_elem *port_state_ptr = port_state_map_cuckoo_lookup(map, &src_ip);
    uint32_t new_state = CLOSED_0;
    if (!port_state_ptr) {
      if (dst_port == PORT_1) {
        new_state = CLOSED_1;
      }
      if (need_session_table) {
        struct array_elem elem;
        elem.state = new_state;
        port_state_map_cuckoo_insert(map, &src_ip, &elem);
        bpf_log_debug("[update_state_by_metadata] insert state %d for src ip %04x",
                       new_state, src_ip);
      }
    } else {
      new_state = get_new_state(port_state_ptr->state, dst_port);
      port_state_ptr->state = new_state;
      if (md_elem->tcp_fin_flag) {
        port_state_map_cuckoo_delete(map, &src_ip);
        bpf_log_debug("[update_state_by_metadata] remove state %d for src ip %04x",
                       new_state, src_ip);
      } else {
        bpf_log_debug("[update_state_by_metadata] new state %d for src ip %04x",
                       new_state, src_ip);
      }
    }
    return new_state;
}

/* metadata_log is used to sync up information across cores
 * METADATA_LOG_MAX_ENTIRES should be 2^n
 */
#define METADATA_LOG_MAX_ENTIRES 2048
struct metadata_log_elem {
  int id;
  struct metadata_elem metadata;
} __attribute__((packed));

struct metadata_log_t {
  int start_loc;
  int end_loc; // range: [0, METADATA_LOG_MAX_ENTIRES-1]
  // int pkt_min;
  int pkt_max;
  // id in ring is increasing from start_loc to end_loc
  // or [start_loc, -1], [0, end_loc]
  struct metadata_log_elem ring[METADATA_LOG_MAX_ENTIRES];
} __attribute__((packed));

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __type(key, u32);
  __type(value, struct metadata_log_t);
  __uint(max_entries, 1);
} metadata_log SEC(".maps");

static inline void print_md(struct metadata_elem *md) {
  if (!md) {
    bpf_log_err("[print_md] null pointer");
    return;
  }
  bpf_log_info("src ip %04x, dst port: %d, tcp_syn_flag: %d, tcp_fin_flag: %d",
               ntohl(md->src_ip), md->dst_port,
               md->tcp_syn_flag, md->tcp_fin_flag);
}

static inline void print_log_md(struct metadata_log_elem *md) {
  if (!md) {
    bpf_log_err("[print_log_md] null pointer");
    return;
  }
  print_md(&md->metadata);
}

static inline void add_metadata_to_log(struct metadata_log_t *log,
                                       struct metadata_elem *md,
                                       int pkt_id) {
  // if ((!log) || (!md)) {
  //   return;
  // }
  // int pkt_id = pkt_id_in;
  int next_loc = log->end_loc + 1;
  if (log->pkt_max <= 0) {
    next_loc = log->end_loc;
  }
  next_loc = next_loc & (METADATA_LOG_MAX_ENTIRES - 1);
  log->end_loc = next_loc;
  log->ring[next_loc].id = pkt_id;
  memcpy_cilium(&log->ring[next_loc].metadata, md, sizeof(struct metadata_elem));
  // if overwrite, need to update log->start_loc
  if ((log->pkt_max > 0) && (next_loc == log->start_loc)) {
    log->start_loc = (log->start_loc + 1) & (METADATA_LOG_MAX_ENTIRES - 1);
  }
  log->pkt_max = pkt_id;
  // update log info
  bpf_log_info("[add_metadata_to_log] add pkt %d to ring[%d], loc_s: %d, loc_e: %d, pkt_max: %d",
               pkt_id, next_loc, log->start_loc, log->end_loc, log->pkt_max);
  print_md(&log->ring[next_loc].metadata);
}

static inline bool pkt_processed_at_core(struct metadata_log_t *log,
                                         int pkt_id) {
  return (log->pkt_max >= pkt_id);
}

struct binary_search_id_in_log_iter_ctx {
  int pkt_id;
  int low;
  int high;
  struct metadata_log_t *log;
  int loc;
};

static inline int binary_search_id_in_log_iter(__u32 index, void *data) {
  struct binary_search_id_in_log_iter_ctx *ctx = data;
  int pkt_id = ctx->pkt_id;
  struct metadata_log_t *log = ctx->log;
  if (ctx->low > ctx->high) {
    return 1;
  }
  int mid = (ctx->low + ctx->high) >> 1;
  int loc = mid & (METADATA_LOG_MAX_ENTIRES - 1);
  int id_in_loc = log->ring[loc].id;
  // printf("l:%d, h:%d, m:%d; %d ? %d\n", l, h, m, id_in_loc, pkt_id);
  if (id_in_loc == pkt_id) {
    ctx->loc = loc;
    return 1;
  } else if (id_in_loc < pkt_id) {
    ctx->low = mid + 1;
  } else {
    ctx->high = mid - 1;
  }
  return 0;
}

static inline int binary_search_id_in_log(struct metadata_log_t *log,
                                          int pkt_id) {
  // Use binary search
  int l = log->start_loc;
  int h = log->end_loc;
  if (l > h) {
    h = l + METADATA_LOG_MAX_ENTIRES;
  }
  // int loc = l & (METADATA_LOG_MAX_ENTIRES - 1);
  // int id = log->ring[loc].id;
  struct binary_search_id_in_log_iter_ctx loop_ctx = {
    .pkt_id = pkt_id,
    .low = l,
    .high = h,
    .log = log,
    .loc = -1,
  };
  // loop_ctx.loc = 0;
  const int num_loop_max = 13; // since METADATA_LOG_MAX_ENTIRES is 2048
  bpf_loop(num_loop_max, binary_search_id_in_log_iter, &loop_ctx, 0);
  // loc = loop_ctx.loc & (METADATA_LOG_MAX_ENTIRES - 1);
  // int find_id = log->ring[loc].id;
  // if ((id > pkt_id) && (loop_ctx.loc >= 0)) {
  //   bpf_log_err("[ERROR] id %d > pkt_id %d, find id: %d", id, pkt_id, find_id);
  // }
  return loop_ctx.loc;
}

static inline void get_pkt_metadata_from_log(struct metadata_log_t *log,
                                             int pkt_id,
                                             bool *lost,
                                             struct metadata_elem *md_dst) {
  *lost = true;
  if (log->pkt_max <= 0) return;
  // find out the location of pkt_id
  int loc = binary_search_id_in_log(log, pkt_id);
  bpf_log_info("find loc: %d", loc);
  // pkt_id is lost at core
  if (loc < 0) {
    return;
  }
  loc = loc & (METADATA_LOG_MAX_ENTIRES - 1);
  int id = log->ring[loc].id;
  // // Check if the metadata has been overwritten
  // const int safety_offset = 2;
  // int start_loc = log->start_loc;
  // int min_loc = (start_loc + safety_offset) & (METADATA_LOG_MAX_ENTIRES - 1);
  // int log_pkt_min = log->ring[min_loc].id;
  // if ((start_loc > 0) && (pkt_id < log_pkt_min)) {
  //   bpf_log_err("[ERROR] Need to increase log size: pkt_id: %d, log_pkt_min: %d, id: %d",
  //               pkt_id, log_pkt_min, id);
  // }
  *lost = false;
  memcpy_cilium(md_dst, &log->ring[loc].metadata, sizeof(struct metadata_elem));
}

// If # of lost packets >= BURSTY_LOSS_THRESHOLD,
// We assume packet loss is due to congestion instead of
// loss configured in the pcap file
#define CONGESTED_LOSS_THRESHOLD (NUM_PKTS + 1)
// int cores[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
// #define NUM_CORES 16
#if NUM_PKTS == 2
  int cores[] = {9, 10, 11};
#elif NUM_PKTS == 3
  int cores[] = {9, 10, 11};
#elif NUM_PKTS == 4
  int cores[] = {9, 10, 11, 12};
#elif NUM_PKTS == 5
  int cores[] = {9, 10, 11, 12, 13};
#elif NUM_PKTS == 6
  int cores[] = {9, 10, 11, 12, 13, 14};
#elif NUM_PKTS == 7
  int cores[] = {9, 10, 11, 12, 13, 14, 15};
#elif NUM_PKTS == 8
  int cores[] = {9, 10, 11, 12, 13, 14, 15, 1};
#elif NUM_PKTS == 9
  int cores[] = {9, 10, 11, 12, 13, 14, 15, 1, 2};
#elif NUM_PKTS == 10
  int cores[] = {9, 10, 11, 12, 13, 14, 15, 1, 2, 3};
#elif NUM_PKTS == 11
  int cores[] = {9, 10, 11, 12, 13, 14, 15, 1, 2, 3, 4};
#elif NUM_PKTS == 12
  int cores[] = {9, 10, 11, 12, 13, 14, 15, 1, 2, 3, 4, 5};
#elif NUM_PKTS == 13
  int cores[] = {9, 10, 11, 12, 13, 14, 15, 1, 2, 3, 4, 5, 6};
#elif NUM_PKTS == 14
  int cores[] = {9, 10, 11, 12, 13, 14, 15, 1, 2, 3, 4, 5, 6, 7};
#else
  int cores[] = {9};
#endif
// int cores[] = {9, 10};
u64 LOST_FLAGS = 0;

static inline void init_expected_lost_flags() {
  LOST_FLAGS = 0;
  for (int i = 0; i < NUM_PKTS; i++) {
    LOST_FLAGS |= 1 << cores[i];
  }
  bpf_log_debug("init LOST_FLAGS: 0x%x", LOST_FLAGS);
}

static inline bool is_pkt_lost_at_all_cores(u64 lost_flags) {
  return ((lost_flags & LOST_FLAGS) == LOST_FLAGS);
}

static inline void set_pkt_lost_at_core(int core, u64 *lost_flags) {
  *lost_flags |= 1 << core;
  // bpf_log_debug("[set_pkt_lost_at_core] core: %d, lost_flags: 0x%x", core, *lost_flags);
}

static inline bool is_pkt_lost_at_core(int core, u64 lost_flags) {
  bool flag = lost_flags & (1 << core);
  // bpf_log_debug("[is_pkt_lost_at_core] core: %d(0x%x), lost_flags: 0x%x", 
  //               core, core, lost_flags);
  return flag;
}

struct handle_one_packet_loss_use_other_log_ctx {
  u64 lost_flags;
  int pkt_id;
  bool recover_flag;
  struct port_state_map_cuckoo_hash_map *map;
  // bool aborted;
  int min_pkt_id_other_logs;
  int max_pkt_id_other_logs;
};

static inline int handle_one_packet_loss_use_other_log(__u32 index, void *data) {
  struct handle_one_packet_loss_use_other_log_ctx *ctx = data;
  int i = ctx->pkt_id;
  u64 lost_flags = ctx->lost_flags;
  ctx->min_pkt_id_other_logs = INT_MAX;
  ctx->max_pkt_id_other_logs = 0;
  for (int j = 0; j < NUM_PKTS; j++) {
    int core = cores[j];
    if (is_pkt_lost_at_core(core, lost_flags)) {
      continue;
    }
    struct metadata_elem md = {
      .src_ip = 0,
      .dst_port = 0,
      .tcp_syn_flag = false,
      .tcp_fin_flag = false
    };
    int log_index = 0;
    // We might need to cache metadata_log_t
    struct metadata_log_t *md_log = bpf_map_lookup_percpu_elem(&metadata_log, 
                                                               &log_index, core);
    if (!md_log) {
      bpf_log_err("[ERROR][handle_packet_loss] no md_log of core %d found", core);
      return 1;
    }
    int pkt_max_at_core = 0;
    if (! pkt_processed_at_core(md_log, i)) {
      continue;
    }
    bool lost = true;
    get_pkt_metadata_from_log(md_log, i, &lost, &md);
    if (lost) {
      set_pkt_lost_at_core(core, &lost_flags);
      bpf_log_debug("[handle_packet_loss] pkt %d is lost at core %d", i, core);
      if (is_pkt_lost_at_all_cores(lost_flags)) {
        bpf_log_info("[handle_packet_loss] pkt %d lost at all cores. Don't need to recover state", i);
        ctx->recover_flag = true;
        return 1;
      }
      continue;
    }
    // Recover the state
    bpf_log_info("[handle_packet_loss] get metadata of pkt %d from core %d", i, core);
    print_md(&md);
    // todo: call state transition
    update_state_by_metadata(&md, ctx->map);
    ctx->recover_flag = true;
    return 1;
  }
  return 0;
}

struct handle_one_packet_loss_ctx {
  int lost_pkt_max;
  int next_pkt_to_process;
  int cur_core;
  struct metadata_log_t *cur_md_log;
  struct port_state_map_cuckoo_hash_map *map;
  // bool aborted;
};

static inline int handle_one_packet_loss(__u32 index, void *data) {
  struct handle_one_packet_loss_ctx *ctx = data;
  int i = ctx->next_pkt_to_process;
  bpf_log_debug("[handle_one_packet_loss] next pkt to recover: %d, lost_pkt_max: %d", i, ctx->lost_pkt_max);
  if (i > ctx->lost_pkt_max) {
    return 1; // break loop
  }
  bpf_log_info("[handle_one_packet_loss] to recover pkt %d", i);
  struct handle_one_packet_loss_use_other_log_ctx loop_ctx = {
    .lost_flags = 0,
    .pkt_id = i,
    .recover_flag = false,
    .map = ctx->map,
    // .aborted = false,
    /* monitor the progress in other logs */
    .min_pkt_id_other_logs = 0,
    .max_pkt_id_other_logs = 0,
  };
  set_pkt_lost_at_core(ctx->cur_core, &loop_ctx.lost_flags);
  bpf_loop(BPF_LOOP_MAX, handle_one_packet_loss_use_other_log, &loop_ctx, 0);
  // ctx->aborted = loop_ctx.aborted;
  if (!loop_ctx.recover_flag) {
    bpf_log_err("[handle_one_packet_loss] recover pkt %d FAIL! Wait time is not enough: other cores processed [%d, %d]",
                i, loop_ctx.min_pkt_id_other_logs, loop_ctx.max_pkt_id_other_logs);
    return 1;
  } else {
    bpf_log_info("[handle_one_packet_loss] recover pkt %d SUCCEED", i);
  }
  ctx->next_pkt_to_process++;
  return 0;
}

static inline void handle_packet_loss(u32 cur_core,
                                      struct xdp_md *ctx,
                                      struct metadata_log_t *cur_md_log,
                                      int cur_pkt_id,
                                      struct port_state_map_cuckoo_hash_map *map) {
  // *aborted = false;
  int min_id_in_pkt = cur_pkt_id - (NUM_PKTS - 1);
  min_id_in_pkt = min_id_in_pkt > 1? min_id_in_pkt : 1;
  int max_processed_pkt_id = cur_md_log->pkt_max;
  // Check if there is packet loss
  if (min_id_in_pkt <= max_processed_pkt_id + 1) {
    return;
  }
  // Check if the loss is due to congestion
  int num_lost_pkts = min_id_in_pkt - max_processed_pkt_id - 1;
  bpf_log_info("Detect packet loss, need to recover pkts [%d, %d]",
               max_processed_pkt_id + 1, min_id_in_pkt - 1);
  // Need to update log->pkt_max to avoid deadlock (other cores waiting)!
  cur_md_log->pkt_max = min_id_in_pkt - 1;
  if (num_lost_pkts >= CONGESTED_LOSS_THRESHOLD) {
    // cur_md_log->num_congested_loss_pkts += num_lost_pkts;
    return;
  }
  bpf_log_info("Detect packet loss, need to recover pkts [%d, %d]",
               max_processed_pkt_id + 1, min_id_in_pkt - 1);
  init_expected_lost_flags();
  // Get information from other cores
  struct handle_one_packet_loss_ctx loop_ctx = {
    .lost_pkt_max = min_id_in_pkt - 1,
    .next_pkt_to_process = max_processed_pkt_id + 1,
    .cur_core = cur_core,
    .cur_md_log = cur_md_log,
    .map = map,
    // .aborted = false,
  };

  bpf_loop(BPF_LOOP_MAX, handle_one_packet_loss, &loop_ctx, 0);
  // *aborted = loop_ctx.aborted;
  if (loop_ctx.next_pkt_to_process <= loop_ctx.lost_pkt_max) {
    bpf_log_err("[handle_packet_loss] FAIL: next_pkt_to_process: %d <= %d",
                loop_ctx.next_pkt_to_process, loop_ctx.lost_pkt_max);
  } else {
    bpf_log_info("[handle_packet_loss] SUCCEED");
  }
}


SEC("xdp_portknock")
int xdp_prog(struct xdp_md *ctx) {
  u32 cpu = bpf_get_smp_processor_id();
  bpf_log_info("\n");
  bpf_log_info("Receive a packet on cpu %d", cpu);
  int log_index = 0;
  int log_cpu = 1;
  struct metadata_log_t *cur_md_log = bpf_map_lookup_elem(&metadata_log, &log_index);
  // struct metadata_log_t *md_log = bpf_map_lookup_percpu_elem(&metadata_log, &log_index, log_cpu);
  if (!cur_md_log) {
    bpf_log_err("no md_log of core %d found", cpu);
    return XDP_DROP;
  }

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct iphdr *iph;
  u16 h_proto;
  u64 nh_off;
  int rc = XDP_DROP;
  u16 dst_port;
  u32 src_ip;
  u32 cur_pkt_id;

  int dummy_header_size = sizeof(struct ethhdr);
  void* pkt_id_start = data + dummy_header_size;
  int pkt_id_size = sizeof(u32);
  if (pkt_id_start + pkt_id_size > data_end) {
    return XDP_DROP;
  }
  cur_pkt_id = *(u32*)pkt_id_start;
  bpf_log_info("cur_pkt_id: %u", cur_pkt_id);
  // if (cur_pkt_id < cur_md_log->pkt_min) {
  //   bpf_log_info("Reset log");
  //   reset_log(cur_md_log);
  // }

  uint32_t zero = 0;
  struct port_state_map_cuckoo_hash_map *map = bpf_map_lookup_elem(&port_state_map, &zero);
  if (!map) {
    bpf_log_err("port_state_map not found");
    return XDP_DROP;
  }

  // bool aborted = false;
  handle_packet_loss(cpu, ctx, cur_md_log, cur_pkt_id, map);

  struct array_elem *port_state_ptr;
  /* Process latest (n-1) packets using metadata */
  int md_offset = sizeof(struct ethhdr) + sizeof(u32);
  void* md_start = data + md_offset;
  u64 md_size = (NUM_PKTS - 1) * sizeof(struct metadata_elem);
  if (md_start + md_size > data_end)
    return XDP_DROP;

  // copy packet history to its log
  // Skip invalid metadata in packet history
  // If this packet is in the first few packets, there is not enough metadata
  // E.g., there is no packet history in the first packet
  int pkt_history_start_pos = cur_pkt_id >= NUM_PKTS ? 0 : (NUM_PKTS - cur_pkt_id);
  struct metadata_elem *md_elem = md_start;
  // md_elem = md_start;
  struct metadata_elem md = {
    .src_ip = 0,
    .dst_port = 0,
    .tcp_syn_flag = false,
    .tcp_fin_flag = false
  };
  for (int i = pkt_history_start_pos; i < NUM_PKTS - 1; i++) {
    // int pkt_id = cur_pkt_id - (NUM_PKTS - 1 - i);
    // add_metadata_to_log(cur_md_log, cur_pkt_id - (NUM_PKTS - 1 - i), md_elem);
    int a = NUM_PKTS - 1 - i;
    int j = cur_pkt_id - a;
    memcpy_cilium(&md, md_elem, sizeof(struct metadata_elem));
    add_metadata_to_log(cur_md_log, &md, j);
    update_state_by_metadata(&md, map);
    md_elem += 1;
  }

  /* Process the current packet */
  nh_off = dummy_header_size + pkt_id_size + md_size;
  void* pkt_start = data + nh_off;
  struct ethhdr *eth = pkt_start;
  nh_off += sizeof(*eth);
  if (data + nh_off > data_end)
    return XDP_DROP;

  h_proto = eth->h_proto;
  if (h_proto != htons(ETH_P_IP)) {
    return XDP_DROP;
  }

  /* Parse ipv4 header to get protocol, src_ip */
  iph = data + nh_off;
  if (iph + 1 > data_end)
    return XDP_DROP;

  if (iph->protocol != IPPROTO_TCP) {
    return XDP_DROP;
  }
  src_ip = iph->saddr;

  nh_off += sizeof(*iph);
  /* Parse tcp header to get dst_port */
  struct tcphdr *tcp = data + nh_off;
  if (tcp + 1 > data_end)
    return XDP_DROP;
  dst_port = ntohs(tcp->dest);

  // copy the metadata of the current packet to log
  // struct metadata_elem cur_md = {
  //   .src_ip = src_ip,
  //   .dst_port = dst_port,
  //   .tcp_syn_flag = tcp->syn,
  //   .tcp_fin_flag = tcp->fin
  // };
  md.src_ip = src_ip;
  md.dst_port = dst_port;
  md.tcp_syn_flag = tcp->syn;
  md.tcp_fin_flag = tcp->fin;
  add_metadata_to_log(cur_md_log, &md, cur_pkt_id);
  uint32_t new_state = update_state_by_metadata(&md, map);
  if (new_state == OPEN) {
    rc = XDP_PASS;
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";
