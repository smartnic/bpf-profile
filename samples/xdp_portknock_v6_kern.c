/* portknocking using multiple cores, shared-nothing, support loss recovery */
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

/* metadata_log is used to sync up information across cores
 * METADATA_LOG_MAX_ENTIRES should be 2^n
 */
#define METADATA_LOG_MAX_ENTIRES 8
struct metadata_log_elem {
  bool valid;
  struct metadata_elem metadata;
} __attribute__((packed));

struct metadata_log_t {
  int next_loc; // range: [0, METADATA_LOG_MAX_ENTIRES-1]
  int pkt_min;  // pkt_id starts at 1, pkt_min == 0 means no pkt
  int pkt_max;
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
               ntohl(md->src_ip), ntohs(md->dst_port),
               md->tcp_syn_flag, md->tcp_fin_flag);
}

static inline void print_log_md(struct metadata_log_elem *md) {
  if (!md) {
    bpf_log_err("[print_log_md] null pointer");
    return;
  }
  if (md->valid) {
    print_md(&md->metadata);
  } else {
    bpf_log_info("invalid (lost) metadata");
  }
}

/* Add `md` to `log`. If `md` is null, add an invalid metadata */
static inline void add_metadata_to_log(struct metadata_log_t *log,
                                       struct metadata_elem *md) {
  if (!log) {
    return;
  }
  // `& (METADATA_LOG_MAX_ENTIRES - 1)` is to satisfy the verifier
  int loc = log->next_loc & (METADATA_LOG_MAX_ENTIRES - 1);
  if (!md) {
    log->ring[loc].valid = false;
    bpf_log_debug("[add_metadata_to_log] add lost pkt %d to ring[%d]", log->pkt_max+1, loc);
  } else {
    log->ring[loc].valid = true;
    memcpy_cilium(&log->ring[loc].metadata, md, sizeof(struct metadata_elem));
    bpf_log_debug("[add_metadata_to_log] add pkt %d to ring[%d]", log->pkt_max+1, loc);
    print_log_md(&log->ring[loc]);
  }
  // update log information
  log->next_loc = (loc + 1) & (METADATA_LOG_MAX_ENTIRES - 1);
  // If it is the first packet or we need to overwrite a packet,
  // `pkt_min` needs to be updated
  if ((log->pkt_min == 0) || 
      (log->pkt_max - log->pkt_min + 1 >= METADATA_LOG_MAX_ENTIRES)) {
    log->pkt_min++;
  }
  log->pkt_max++;
  bpf_log_debug("[add_metadata_to_log] next_loc: %d, pkt_min: %d pkt_max: %d", 
                log->next_loc, log->pkt_min, log->pkt_max);
}

static inline bool pkt_processed_at_core(struct metadata_log_t *log,
                                         int pkt_id) {
  if (!log) {
    return false;
  }
  return (log->pkt_max >= pkt_id);
}

/* Copy metadata of `pkt_id` from `log` to `md`.
 * If the metadata is overwritten, print error and we need to increase log size
 */
static inline void copy_metadata_from_log(struct metadata_log_t *log,
                                          int pkt_id,
                                          struct metadata_elem *md) {
  if ((!log) || (!md) || (pkt_id == 0)) {
    bpf_log_err("[ERROR][copy_metadata_from_log]");
    return;
  }
  if (!pkt_processed_at_core(log, pkt_id)) {
    bpf_log_err("[ERROR][copy_metadata_from_log] pkt %d NOT processed", pkt_id);
    return;
  }
  int loc = (pkt_id - 1) & (METADATA_LOG_MAX_ENTIRES - 1);
  memcpy_cilium(md, &log->ring[loc].metadata, sizeof(struct metadata_elem));
  // Check if the metadata is overwritten
  const int safety_offset = 1;
  int log_pkt_min = log->pkt_min;
  if ((log->pkt_max > METADATA_LOG_MAX_ENTIRES) &&
      (pkt_id < log_pkt_min + safety_offset)) {
    bpf_log_err("[ERROR][copy_metadata_from_log] need to increase log size! pkt_id: %d, log->pkt_min: %d",
                pkt_id, log_pkt_min);
    // return XDP_ABORTED;
  }
}

static inline bool pkt_lost_at_core(struct metadata_log_t *log,
                                    int pkt_id) {
  if (!log) {
    return false;
  }
  int loc = (pkt_id - 1) & (METADATA_LOG_MAX_ENTIRES - 1);
  bool lost = !(log->ring[loc].valid);
  const int safety_offset = 1;
  int log_pkt_min = log->pkt_min;
  if ((log->pkt_max > METADATA_LOG_MAX_ENTIRES) &&
      (pkt_id < log_pkt_min + safety_offset)) {
    bpf_log_err("[ERROR][pkt_lost_at_core] need to increase log size! pkt_id: %d, log->pkt_min: %d",
                 pkt_id, log_pkt_min);
    return false;
    // return XDP_ABORTED;
  }
  return lost;
}

// int cores[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
// #define NUM_CORES 16
int cores[] = {8, 9};
#define NUM_CORES 2
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
};

static inline int handle_one_packet_loss_use_other_log(__u32 index, void *data) {
  struct handle_one_packet_loss_use_other_log_ctx *ctx = data;
  int i = ctx->pkt_id;
  u64 lost_flags = ctx->lost_flags;
  for (int j = 0; j < NUM_PKTS; j++) {
    int core = cores[j];
    if (is_pkt_lost_at_core(core, lost_flags)) {
      continue;
    }
    int log_index = 0;
    // We might need to cache metadata_log_t
    struct metadata_log_t *md_log = bpf_map_lookup_percpu_elem(&metadata_log, 
                                                               &log_index, core);
    if (!md_log) {
      bpf_log_err("[ERROR][handle_packet_loss] no md_log of core %d found", core);
      return 1;
    }
    if (! pkt_processed_at_core(md_log, i)) {
      continue;
    }
    if (pkt_lost_at_core(md_log, i)) {
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
    struct metadata_elem md = {
      .src_ip = 0,
      .dst_port = 0,
      .tcp_syn_flag = false,
      .tcp_fin_flag = false
    };
    copy_metadata_from_log(md_log, i, &md);
    print_md(&md);
    // todo: call state transition
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
};

static inline int handle_one_packet_loss(__u32 index, void *data) {
  struct handle_one_packet_loss_ctx *ctx = data;
  int i = ctx->next_pkt_to_process;
  bpf_log_debug("[handle_one_packet_loss] next pkt to recover: %d, lost_pkt_max: %d", i, ctx->lost_pkt_max);
  if (i > ctx->lost_pkt_max) {
    return 1; // break loop
  }
  bpf_log_info("[handle_one_packet_loss] to recover pkt %d", i);
  add_metadata_to_log(ctx->cur_md_log, NULL);
  struct handle_one_packet_loss_use_other_log_ctx loop_ctx = {
    .lost_flags = 0,
    .pkt_id = i,
    .recover_flag = false
  };
  set_pkt_lost_at_core(ctx->cur_core, &loop_ctx.lost_flags);
  bpf_loop(BPF_LOOP_MAX, handle_one_packet_loss_use_other_log, &loop_ctx, 0);
  if (!loop_ctx.recover_flag) {
    bpf_log_err("[handle_one_packet_loss] recover pkt %d FAIL! Wait time is not enough", i);
    return 1;
  } else {
    bpf_log_info("[handle_one_packet_loss] recover pkt %d SUCCEED", i);
  }
  ctx->next_pkt_to_process++;
  return 0;
}

static inline void handle_packet_loss(struct xdp_md *ctx, struct metadata_log_t *cur_md_log,
                                      int cur_pkt_id) {
  int min_id_in_pkt = cur_pkt_id - (NUM_PKTS - 1);
  min_id_in_pkt = min_id_in_pkt > 1? min_id_in_pkt : 1;
  int max_processed_pkt_id = cur_md_log->pkt_max;
  // Check if there is packet loss
  if (min_id_in_pkt <= max_processed_pkt_id + 1) {
    return;
  }
  bpf_log_info("Detect packet loss, need to recover pkts [%d, %d]",
               max_processed_pkt_id + 1, min_id_in_pkt - 1);
  init_expected_lost_flags();
  u32 cur_core = bpf_get_smp_processor_id();
  // // Update log first such that other cores know these packets 
  // // are lost on this core. We CANNOT do this after recovering state
  // for (int i = max_processed_pkt_id + 1; i < min_id_in_pkt; i++) {
  //   add_metadata_to_log(cur_md_log, NULL);
  // }
  // Get information from other cores
  struct handle_one_packet_loss_ctx loop_ctx = {
    .lost_pkt_max = min_id_in_pkt - 1,
    .next_pkt_to_process = max_processed_pkt_id + 1,
    .cur_core = cur_core,
    .cur_md_log = cur_md_log
  };

  bpf_loop(BPF_LOOP_MAX, handle_one_packet_loss, &loop_ctx, 0);
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
  bool need_session_table = false;
  bool remove_session_table = false;
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
  handle_packet_loss(ctx, cur_md_log, cur_pkt_id);

  uint32_t zero = 0;
  struct port_state_map_cuckoo_hash_map *map = bpf_map_lookup_elem(&port_state_map, &zero);
  if (!map) {
    bpf_log_err("port_state_map not found");
    return XDP_DROP;
  }

  struct array_elem *port_state_ptr;
  /* Process latest (n-1) packets using metadata */
  int md_offset = dummy_header_size + pkt_id_size;
  void* md_start = data + md_offset;
  u64 md_size = (NUM_PKTS - 1) * sizeof(struct metadata_elem);
  if (md_start + md_size > data_end)
    return XDP_DROP;

  // Skip invalid metadata in packet history
  // If this packet is in the first few packets, there is not enough metadata
  // E.g., there is no packet history in the first packet
  int pkt_history_start_id = cur_pkt_id >= NUM_PKTS ? 0 : (NUM_PKTS - cur_pkt_id);

  // copy packet history to its log
  struct metadata_elem *md_elem = md_start;
  for (int i = pkt_history_start_id; i < NUM_PKTS - 1; i++) {
    add_metadata_to_log(cur_md_log, md_elem);
    md_elem += 1;
  }
  for (int i = pkt_history_start_id; i < NUM_PKTS - 1; i++) {
    md_elem = md_start + i * sizeof(struct metadata_elem);
    need_session_table = md_elem->tcp_syn_flag;
    remove_session_table = md_elem->tcp_fin_flag;
    src_ip = md_elem->src_ip;
    dst_port = md_elem->dst_port;
    port_state_ptr = port_state_map_cuckoo_lookup(map, &src_ip);
    if (!port_state_ptr) {
      uint32_t new_state = CLOSED_0;
      if (dst_port == PORT_1) {
        new_state = CLOSED_1;
      }
      if (need_session_table) {
        struct array_elem elem;
        elem.state = new_state;
        port_state_map_cuckoo_insert(map, &src_ip, &elem);
      }
    } else {
      port_state_ptr->state = get_new_state(port_state_ptr->state, dst_port);
      if (remove_session_table) {
        port_state_map_cuckoo_delete(map, &src_ip);
      }
    }
  }

  /* Process the current packet */
  remove_session_table = false;
  need_session_table = false;
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
  // check if entry needs to be removed
  remove_session_table = tcp->fin;
  // bpf_printk("fin_flag (remove entry): %s", remove_session_table ? "true" : "false");
  need_session_table = tcp->syn;

  // copy the metadata of the current packet to log
  struct metadata_elem cur_md = {
    .src_ip = src_ip,
    .dst_port = dst_port,
    .tcp_syn_flag = tcp->syn,
    .tcp_fin_flag = tcp->fin
  };
  add_metadata_to_log(cur_md_log, &cur_md);

  port_state_ptr = port_state_map_cuckoo_lookup(map, &src_ip);
  if (!port_state_ptr) {
    uint32_t new_state = CLOSED_0;
    if (dst_port == PORT_1) {
      new_state = CLOSED_1;
    }
    if (need_session_table) {
      struct array_elem elem;
      elem.state = new_state;
      port_state_map_cuckoo_insert(map, &src_ip, &elem);
    }
  } else {
    port_state_ptr->state = get_new_state(port_state_ptr->state, dst_port);
    if (port_state_ptr->state == OPEN) {
      rc = XDP_PASS;
    }
    if (remove_session_table) {
      port_state_map_cuckoo_delete(map, &src_ip);
    }
  }

  /* For all valid packets, bounce them back to the packet generator. */
  swap_src_dst_mac(data);
  return XDP_TX;
}

char _license[] SEC("license") = "GPL";

