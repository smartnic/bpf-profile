/*
  map: num | elem | elem
*/
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#define u64 uint64_t

#define MAP_CAPACITY 11

#define FIRST_TABLE 0
#define SECOND_TABLE 1

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
struct hash_table {
  int size;
  struct statemap_elem elem_list[MAP_CAPACITY];
};

/* A hash table */
struct statemap {
  int size;
  struct hash_table table[2];
};

void print_map_elem(struct statemap_elem* elem) {
  struct flow_key flow = elem->flow;
  uint64_t size = elem->size;
  printf("%d 0x%08x:%d -> 0x%08x:%d %lld\n", flow.protocol,
         flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port,
         size);
}

void print_map(struct statemap* map) {
  printf("total map size: %d\n", map->size);
  struct hash_table *table;
  struct statemap_elem *elem;
  for (int i = 0; i < 2; i++) {
    table = &(map->table[i]);
    printf("table %d:\n", i);
    printf("table size: %d\n", table->size);
    for (int j = 0; j < MAP_CAPACITY; j++) {
      elem = &(table->elem_list[j]);
      if (elem->is_filled) {
        printf("%d: ", j);
        print_map_elem(elem);
      }
    }
    printf("\n");
  }
  printf("\n");
}

int insert(struct statemap_elem* new_elem, struct hash_table* table, 
           int hash, int* table_number) { 
  struct statemap_elem* curr_elem = &(table->elem_list[hash]);
  // if the element does not exist, insert the element into the slot
  if (!(curr_elem->is_filled)) {
    (table->size)++;
    memcpy(curr_elem, new_elem, sizeof(struct statemap_elem));
    return 1;
  }
  // if the element already exist in the first table
  //  store the old element to a tmp element
  struct statemap_elem tmp_elem;
  memcpy(&tmp_elem, curr_elem, sizeof(struct statemap_elem));
  //  replace the old element with the new element
  memcpy(curr_elem, new_elem, sizeof(struct statemap_elem));
  //  assign tmp element to the table in the next round
  memcpy(new_elem, &tmp_elem, sizeof(struct statemap_elem));
  //  reverse table_number
  *table_number = !(*table_number);
  return 0;
}

void sync_total_map_size(struct statemap* map) {
  map->size = map->table[0].size + map->table[1].size;
}

void map_insert(struct statemap* map, struct flow_key* flow, u64 size) {
  /* Assume map capacity is large enough */
  struct statemap_elem new_elem;
  int table_number = FIRST_TABLE;
  int hash, status;
  struct hash_table* table;
  memset(&new_elem, 0, sizeof(struct statemap_elem));
  new_elem.flow = *(flow);
  new_elem.size = size;
  new_elem.is_filled = true;
  while (true) {
    if (table_number == FIRST_TABLE) {
      hash = ((new_elem.flow.protocol + new_elem.flow.src_port + new_elem.flow.dst_port) % MAP_CAPACITY);
      printf("at table: %d; actual key: %d; hash key: %d\n", 
            table_number + 1, (new_elem.flow.protocol + new_elem.flow.src_port + new_elem.flow.dst_port), hash);
      status = insert(&new_elem, &(map->table[0]), hash, &table_number);
      if (status) {
        sync_total_map_size(map);
        return;
      }
    } else if (table_number == SECOND_TABLE) {
      hash = (((new_elem.flow.protocol + new_elem.flow.src_port + new_elem.flow.dst_port) / MAP_CAPACITY) % MAP_CAPACITY);
      printf("at table: %d; actual key: %d; hash key: %d\n", 
            table_number + 1, (new_elem.flow.protocol + new_elem.flow.src_port + new_elem.flow.dst_port), hash);
      status = insert(&new_elem, &(map->table[1]), hash, &table_number);
      if (status) {
        sync_total_map_size(map);
        return;
      }
    }
  }
}

uint64_t* map_lookup(struct statemap* map, struct flow_key* flow) {
  struct statemap_elem *elem;
  struct hash_table *table;
  for (int i = 0; i < 2; i++) {
    table = &(map->table[i]);
    for (int j = 0; j < table->size; j++) {
      elem = &(table->elem_list[j]);
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
  }
  return NULL;
}

int main() {
  struct statemap map;
  memset(&map, 0, sizeof(struct statemap));
  /* test case 1: */
  printf("Print map0: empty map\n");
  print_map(&map);

  /* test case 2: */
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

  /* test case 3: */
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

  /* test case 4: */
  /* input keys: {20, 50, 53, 75, 100, 67, 105, 3, 36, 39};, 
     where each key is protocol + src_port + dst_port
  */
  memset(&map, 0, sizeof(struct statemap));
  struct flow_key flow3 = {
    .protocol = 17,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101013,
    .src_port = 2,
    .dst_port = 1
  };
  struct flow_key flow4 = {
    .protocol = 30,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101014,
    .src_port = 10,
    .dst_port = 10
  };
  struct flow_key flow5 = {
    .protocol = 30,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101014,
    .src_port = 1,
    .dst_port = 22
  };
  struct flow_key flow6 = {
    .protocol = 50,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101014,
    .src_port = 15,
    .dst_port = 10
  };
  struct flow_key flow7 = {
    .protocol = 70,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101014,
    .src_port = 10,
    .dst_port = 20
  };
  struct flow_key flow8 = {
    .protocol = 50,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101014,
    .src_port = 10,
    .dst_port = 7
  };
  struct flow_key flow9 = {
    .protocol = 100,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101014,
    .src_port = 2,
    .dst_port = 3
  };
  struct flow_key flow10 = {
    .protocol = 1,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101014,
    .src_port = 1,
    .dst_port = 1
  };
  struct flow_key flow11 = {
    .protocol = 30,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101014,
    .src_port = 3,
    .dst_port = 3
  };
  struct flow_key flow12 = {
    .protocol = 30,
    .src_ip = 0x10101010,
    .dst_ip = 0x10101014,
    .src_port = 4,
    .dst_port = 5
  };
  struct flow_key flow_array [] = {flow3, flow4, flow5, flow6, flow7, flow8, flow9, flow10, flow11, flow12};
  for (int i = 0; i < (sizeof(flow_array) / sizeof(struct flow_key)); i++) {
    int value = flow_array[i].protocol + flow_array[i].src_port + flow_array[i].dst_port;
    map_insert(&map, &(flow_array[i]), value);
    printf("Print map3: map3 = insert(map1, flow%d, %d)\n", i, value);
    print_map(&map);
    size = map_lookup(&map, &(flow_array[i]));
    if (size) {
      printf("Lookup(map3, flow%d) = %d\n\n", i + 3, value); // *size should be equal to 128
    }
  }
  return 0;
}
