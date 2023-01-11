/*
  map: num | elem | elem
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#define u64 uint64_t

#define MAP_CAPACITY 1024

struct flow_key {
  uint8_t protocol;
  uint32_t src_ip;
  uint32_t dst_ip;
  uint16_t src_port;
  uint16_t dst_port;
};

struct statemap_elem {
  bool is_filled;
  struct flow_key flow;
  uint64_t size;
};

/* A hash table */
struct statemap {
  int size;
  struct statemap_elem elem_list[MAP_CAPACITY];
};

void print_map_elem(struct statemap_elem* elem) {
  struct flow_key flow = elem->flow;
  uint64_t size = elem->size;
  printf("%d 0x%08x:%d -> 0x%08x:%d %lld\n", flow.protocol,
         flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
         size);
}

void print_map(struct statemap* map) {
  printf("map size: %d\n", map->size);
  struct statemap_elem *elem;
  for (int i = 0; i < MAP_CAPACITY; i++) {
    elem = &(map->elem_list[i]);
    if (elem->is_filled) {
      printf("%d: ", i);
      print_map_elem(elem);
    }
  }
  printf("\n");
}

void map_insert(struct statemap* map, struct flow_key* flow, u64 size) {
  /* Assume map capacity is large enough */
  if (map->size < MAP_CAPACITY) {
    struct statemap_elem *elem = &(map->elem_list[map->size]);
    if (elem->is_filled) {
      printf("Insert failed.");
      return;
    }
    elem->flow = *flow;
    elem->size = size;
    elem->is_filled = true;
    map->size += 1;
  }
}

uint64_t* map_lookup(struct statemap* map, struct flow_key* flow) {
  struct statemap_elem *elem;
  for (int i = 0; i < map->size; i++) {
    elem = &(map->elem_list[i]);
    if (!elem->is_filled) {
      continue;
    }
    if (elem->flow.protocol == flow->protocol &&
        elem->flow.src_ip == flow->src_ip &&
        elem->flow.dst_ip == flow->dst_ip &&
        elem->flow.src_port == flow->src_port &&
        elem->flow.dst_port == flow->dst_port) {
      return &(elem->size);
    }
  }
  return NULL;
}

int main() {
  struct statemap map;
  memset(&map, 0, sizeof(struct statemap));
  printf("Print map0: empty map\n");
  print_map(&map);

  struct flow_key flow1 = {
    .protocol = 17,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101011,
    .src_port = 1,
    .dst_port = 2
  };
  map_insert(&map, &flow1, 128);
  printf("Print map1: map1 = insert(map0, flow1, 128)\n");
  print_map(&map);

  uint64_t* size = map_lookup(&map, &flow1);
  if (size) {
    printf("Lookup(map1, flow1) = %llu\n", *size); // *size should be equal to 128
  }

  struct flow_key flow2 = {
    .protocol = 17,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101012,
    .src_port = 3,
    .dst_port = 4
  };
  map_insert(&map, &flow2, 64);
  printf("Print map2: map2 = insert(map1, flow2, 64)\n");
  print_map(&map);
  size = map_lookup(&map, &flow2);
  if (size) {
    printf("Lookup(map2, flow2) = %llu\n", *size); // *size should be equal to 64
  }

  return 0;
}
