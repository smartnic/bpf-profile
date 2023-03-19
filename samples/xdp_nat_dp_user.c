// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 PLUMgrid
 */
#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <libgen.h>
#include <net/if.h>

#include "bpf_util.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>

#define NAT_SRC 1
#define NAT_DST 2
#define NAT_MSQ 3
#define NAT_PFW 4

static int ifindex;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static __u32 prog_id;

static void int_exit(int sig)
{
  __u32 curr_prog_id = 0;

  if (bpf_xdp_query_id(ifindex, xdp_flags, &curr_prog_id)) {
    printf("bpf_xdp_query_id failed\n");
    exit(1);
  }
  if (prog_id == curr_prog_id)
    bpf_xdp_detach(ifindex, xdp_flags, NULL);
  else if (!curr_prog_id)
    printf("couldn't find a prog id on a given interface\n");
  else
    printf("program on interface changed, not removing\n");
  exit(0);
}

static void usage(const char *prog)
{
  fprintf(stderr,
          "usage: %s [OPTS] IFACE\n\n"
          "OPTS:\n"
          "    -S    use skb-mode\n"
          "    -N    enforce native mode\n"
          "    -F    force loading prog\n"
          "    -I    input program file\n",
          prog);
}

// * struct sm_k
// * struct sm_v
struct sm_k {
  __u32 internal_netmask_len;
  __be32 internal_ip;
};
struct sm_v {
  __be32 external_ip;
  uint8_t entry_type;
};
static void init_sm_rules(int map_fd)
{
  struct sm_k key = {0, 0};
  key.internal_netmask_len = 32;
  key.internal_ip = inet_addr("10.10.1.2");
  struct sm_v value = {0, 0};
  value.external_ip = inet_addr("10.10.1.10");
  value.entry_type = NAT_SRC;
  int res = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
  printf("init maps res: %d (0 means success).\n", res);
}

int main(int argc, char **argv)
{
  struct bpf_prog_info info = {};
  __u32 info_len = sizeof(info);
  const char *optstr = "FSNI";
  int prog_fd, map_fd, opt;
  struct bpf_program *prog;
  struct bpf_object *obj;
  struct bpf_map *map;
  char filename[256];
  int err;

  while ((opt = getopt(argc, argv, optstr)) != -1) {
    switch (opt) {
    case 'S':
      xdp_flags |= XDP_FLAGS_SKB_MODE;
      break;
    case 'N':
      ifindex = if_nametoindex(argv[optind]);
      break;
    case 'F':
      xdp_flags &= ~XDP_FLAGS_UPDATE_IF_NOEXIST;
      break;
    case 'I':
      printf("parameter is:%s\n", argv[optind]);
      snprintf(filename, sizeof(filename), "%s_kern.o", argv[optind]);
      break;
    default:
      usage(basename(argv[0]));
      return 1;
    }
  }

  if (!(xdp_flags & XDP_FLAGS_SKB_MODE))
    xdp_flags |= XDP_FLAGS_DRV_MODE;

  if (optind == argc) {
    usage(basename(argv[0]));
    return 1;
  }

  if (!ifindex) {
    perror("if_nametoindex");
    return 1;
  }

  printf("bpf_prog=%s\n", filename);
  // snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
  obj = bpf_object__open_file(filename, NULL);
  if (libbpf_get_error(obj))
    return 1;

  prog = bpf_object__next_program(obj, NULL);
  bpf_program__set_type(prog, BPF_PROG_TYPE_XDP);

  err = bpf_object__load(obj);
  printf("program is loaded\n");
  if (err)
    return 1;

  prog_fd = bpf_program__fd(prog);

  const char* map_name = "sm_rules";
  map = bpf_object__find_map_by_name(obj, map_name);
  if (!map) {
    printf("finding a map in obj file failed\n");
    return 1;
  }
  map_fd = bpf_map__fd(map);

  if (!prog_fd) {
    printf("bpf_prog_load_xattr: %s\n", strerror(errno));
    return 1;
  }

  signal(SIGINT, int_exit);
  signal(SIGTERM, int_exit);

  if (bpf_xdp_attach(ifindex, prog_fd, xdp_flags, NULL) < 0) {
    printf("link set xdp fd failed\n");
    return 1;
  }

  err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
  if (err) {
    printf("can't get prog info - %s\n", strerror(errno));
    return err;
  }
  prog_id = info.id;

  init_sm_rules(map_fd);
  while (1) {}

  return 0;
}