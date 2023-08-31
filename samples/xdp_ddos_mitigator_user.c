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
#include "lib/fasthash.h"
#include "lib/usr_lib/cuckoo_usr.h"

#define NOT_FOUND 0
#define PERCPU_MAP 1
#define HASH_MAP 2
#define CUCKOO_HASH_MAP 3
#define CUCKOO_HASH_MAP_SHARED_CPU 4

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

static int get_map_type(char* filename) {
  if (strstr(filename, "v1")) {
    return HASH_MAP;
  } else if (strstr(filename, "v2")) {
    return PERCPU_MAP;
  } else if (strstr(filename, "v4") || strstr(filename, "v5")) {
    return CUCKOO_HASH_MAP;
  }
  return NOT_FOUND;
}

// * key (uint32_t): ipv4 address.
// * value (u64): 0 (used for matched rules counters)
static void update_blocklist(int map_fd, int map_type, char* map_key)
{
  __u32 key = inet_addr(map_key);
  __u64 value = 0;
  int res;
  printf("key: %04x, value: 0\n", key);
  if (map_type == HASH_MAP) {
    res = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
  } else if (map_type == PERCPU_MAP) {
    unsigned int nr_cpus = bpf_num_possible_cpus();
    __u64 value_arr[nr_cpus];
    for (int i = 0; i < nr_cpus; i++) {
      value_arr[i] = value;
    }
    res = bpf_map_update_elem(map_fd, &key, value_arr, BPF_ANY);
  } else if ((map_type == CUCKOO_HASH_MAP) ||
             (map_type == CUCKOO_HASH_MAP_SHARED_CPU)) {
    int map_size = 512;
    cuckoo_error_t err_map;
    memset(&err_map, 0, sizeof(err_map));
    /* Init userspace cuckoo hashmap */
    cuckoo_hashmap_t *cuckoo_map = cuckoo_table_init_by_fd(map_fd, sizeof(__u32),
                                   sizeof(__u64), map_size, true, &err_map);
    if (cuckoo_map == NULL) {
      printf("cuckoo_table_init_by_fd failed\n");
      printf("%s\n", err_map.error_msg);
      res = -1;
    } else {
      res = cuckoo_insert(cuckoo_map, &key, &value, sizeof(key), sizeof(value), &err_map);
    }
  } else {
    res = bpf_map_update_elem(map_fd, &key, &value, BPF_ANY);
  }
  printf("init maps res: %d (0 means success).\n", res);
}

// * key (uint32_t): ipv4 address.
// * value (u64): used for matched rules counters.
static void init_blocklist(int map_fd, int map_type, char* srcip_file)
{
  FILE *file = fopen(srcip_file, "r");
  if (file == NULL) {
    printf("Error opening file\n");
    return;
  }
  char ip[50];
  while (fgets(ip, sizeof(ip), file) != NULL) {
    printf("insert ip: %s", ip);
    update_blocklist(map_fd, map_type, ip);
  }
  fclose(file);
}

int main(int argc, char **argv)
{
  struct bpf_prog_info info = {};
  __u32 info_len = sizeof(info);
  const char *optstr = "FSNIA";
  int prog_fd, map_fd, opt;
  struct bpf_program *prog;
  struct bpf_object *obj;
  struct bpf_map *map;
  char filename[256];
  char srcip_file[512];
  int err;
  int map_type;

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
    case 'A': /* src ip file name */
      printf("src ip file is:%s\n", argv[optind]);
      snprintf(srcip_file, sizeof(srcip_file), "%s", argv[optind]);
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

  const char* map_name = "srcblocklist";
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

  map_type = get_map_type(filename);
  init_blocklist(map_fd, map_type, srcip_file);
  while (1) {}

  return 0;
}
