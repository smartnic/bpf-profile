/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright (c) 2023 Sebastiano Miano <mianosebastiano@gmail.com> */

#include "cuckoo_usr.h"

#include "../fasthash.h"
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <linux/kernel.h>

#define LOG2(x)                                                                                    \
    ({                                                                                             \
        unsigned _x = (x);                                                                         \
        unsigned _result = 0;                                                                      \
        while (_x >>= 1) {                                                                         \
            _result++;                                                                             \
        }                                                                                          \
        _result;                                                                                   \
    })

int roundup(int value, int boundary) {
    return (value + boundary - 1) / boundary * boundary;
}

cuckoo_hashmap_t *cuckoo_table_init_by_fd(int map_fd, size_t key_size, size_t value_size,
                                          uint32_t max_entries, bool aligned, cuckoo_error_t *err) {

    /* Check if err is not NULL */
    if (err == NULL) {
        return NULL;
    }

    unsigned int num_cpus = 1;
    /* Calculating the size of every hash_cell */
    size_t hash_cell_size = 0;
    size_t key_offset = sizeof(bool);
    size_t value_offset = sizeof(bool) + key_size;
    hash_cell_size += sizeof(bool);
    hash_cell_size += key_size;
    hash_cell_size += value_size;

    /* Since the BPF structure is aligned to 4, I need to round it if it is not aligned */
    if (aligned) {
        if (hash_cell_size % 8 != 0) {
            hash_cell_size = (hash_cell_size / 8 + 1) * 8;
        }
        key_offset = 4; // need to fix later, this is for ddos
        value_offset = 8;
    }

    /* Calculating the size of the table inside the map */
    size_t table_size = 0;
    size_t hash_cell_array_offset = sizeof(int);
    table_size += sizeof(int);
    table_size += (hash_cell_size * max_entries);

    /* Since the BPF structure is aligned to 4, I need to round it if it is not aligned */
    if (aligned) {
        if (table_size % 8 != 0) {
            table_size = (table_size / 8 + 1) * 8;
        }
        hash_cell_array_offset = roundup(sizeof(int), 8);
    }

    /* Calculating the size of the map */
    size_t map_size = 0;
    size_t table1_offset = sizeof(int);
    map_size += sizeof(int);
    map_size += table_size; /* First hash table */
    map_size += table_size; /* Second hash table */

    /* Since the BPF structure is aligned to 4, I need to round it if it is not aligned */
    if (aligned) {
        if (map_size % 8 != 0) {
            map_size = (map_size / 8 + 1) * 8;
        }
        table1_offset = roundup(sizeof(int), 8);
    }
    size_t table2_offset = table1_offset + table_size;

    struct bpf_map_info info;
    __u32 len = sizeof(info);
    memset(&info, 0, len);

    int ret = bpf_obj_get_info_by_fd(map_fd, &info, &len);
    if (ret) {
        err->error_code = ret;
        snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                 "Failed to get map info for fd (%d)", map_fd);
        return NULL;
    }

    /* Check if map size is equal to the size we calculated */
    if (info.value_size != map_size) {
        err->error_code = map_fd;
        snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                 "Map value (%d) is not equal to the size we calculated (%ld)", info.value_size,
                 map_size);
        return NULL;
    }

    /* Check if the key is the one we expect */
    if (info.key_size != sizeof(uint32_t)) {
        err->error_code = map_fd;
        snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                 "Map key (%d) is not equal to the size we expect (%ld)", info.key_size,
                 sizeof(uint32_t));
        return NULL;
    }

    /* Check if the map type is also what we expect */
    if (info.type != BPF_MAP_TYPE_PERCPU_ARRAY && info.type != BPF_MAP_TYPE_ARRAY) {
        err->error_code = map_fd;
        snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                 "Map type (%d) is not equal to the size we expect (%d or %d)", info.type,
                 BPF_MAP_TYPE_PERCPU_ARRAY, BPF_MAP_TYPE_ARRAY);
        return NULL;
    }

    /* Check the entries in the map */
    if (info.max_entries != 1) {
        err->error_code = map_fd;
        snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                 "Map max entries (%d) is not equal to the size we expect (%d)", info.max_entries,
                 1);
        return NULL;
    }

    cuckoo_hashmap_t *map = malloc(sizeof(cuckoo_hashmap_t));
    if (map == NULL) {
        err->error_code = map_fd;
        strncpy(err->error_msg, "Failed to allocate memory for the hashmap", CUCKOO_ERROR_MSG_SIZE);
        return NULL;
    }

    if (info.type == BPF_MAP_TYPE_PERCPU_ARRAY) {
        num_cpus = libbpf_num_possible_cpus();
    }

    map->map_fd = map_fd;
    map->map_id = info.id;
    map->map_type = info.type;
    map->num_cpus = num_cpus;
    map->key_size = key_size;
    map->value_size = value_size;
    map->max_entries = max_entries;
    map->hash_cell_size = hash_cell_size;
    map->table_size = table_size;
    map->entire_map_size = map_size;
    map->key_offset = key_offset;
    map->value_offset = value_offset;
    map->hash_cell_array_offset = hash_cell_array_offset;
    map->table1_offset = table1_offset;
    map->table2_offset = table2_offset;
    return map;
}

cuckoo_hashmap_t *cuckoo_table_init_by_id(int map_id, size_t key_size, size_t value_size,
                                          uint32_t max_entries, bool aligned, cuckoo_error_t *err) {
    /* Check if err is not NULL */
    if (err == NULL) {
        return NULL;
    }

    int map_fd = bpf_map_get_fd_by_id(map_id);

    if (map_fd < 0) {
        err->error_code = map_fd;
        strncpy(err->error_msg, "Failed to get map fd", CUCKOO_ERROR_MSG_SIZE);
        return NULL;
    }

    return cuckoo_table_init_by_fd(map_fd, key_size, value_size, max_entries, aligned, err);
}

typedef struct {
    const void *key_to_insert;
    const void *value_to_insert;
    size_t key_size;
    size_t value_size;
    int loop_cnt;
    uint32_t h1;
    uint32_t h2;
    void *t1_ptr;
    void *t2_ptr;
    void *map_ptr;
} loop_ctx_t;

bool cuckoo_insert_loop(const cuckoo_hashmap_t *map, loop_ctx_t *ctx, cuckoo_error_t *err) {
    void *x_key = malloc(ctx->key_size);
    void *x_value = malloc(ctx->value_size);
    void *tmp_key = malloc(ctx->key_size);
    void *tmp_value = malloc(ctx->value_size);
    bool tmp_is_filled;
    bool x_is_filled = true;

    if (x_key == NULL || x_value == NULL || tmp_key == NULL || tmp_value == NULL) {
        err->error_code = -1;
        strncpy(err->error_msg, "Failed to allocate memory for the key and value",
                CUCKOO_ERROR_MSG_SIZE);
        return false;
    }

    memcpy(x_key, ctx->key_to_insert, ctx->key_size);
    memcpy(x_value, ctx->value_to_insert, ctx->value_size);

    for (int i = 0; i < ctx->loop_cnt; i++) {
        uint32_t idx = ctx->h1 & (map->max_entries - 1);
        void *elem = ctx->t1_ptr + map->hash_cell_array_offset + (idx * map->hash_cell_size);

        /* Copy map element into tmp */
        tmp_is_filled = *(bool *)elem;
        memcpy(tmp_key, elem + map->key_offset, ctx->key_size);
        memcpy(tmp_value, elem + map->value_offset, ctx->value_size);

        /* Copy x into map */
        *(bool *)elem = x_is_filled;
        memcpy(elem + map->key_offset, x_key, ctx->key_size);
        memcpy(elem + map->value_offset, x_value, ctx->value_size);

        if (!tmp_is_filled) {
            // Increase table size
            (*(int *)ctx->t1_ptr)++;
            // Increase total map current size
            (*(int *)ctx->map_ptr)++;

            free(x_key);
            free(x_value);
            free(tmp_key);
            free(tmp_value);
            return true;
        }

        /* Copy tmp into x */
        x_is_filled = tmp_is_filled;
        memcpy(x_key, tmp_key, ctx->key_size);
        memcpy(x_value, tmp_value, ctx->value_size);

        /* Calculate new hash */
        ctx->h2 = fasthash32(x_key, ctx->key_size, HASH_SEED_2);
        idx = ctx->h2 & (map->max_entries - 1);

        elem = ctx->t2_ptr + map->hash_cell_array_offset + (idx * map->hash_cell_size);

        /* Copy map element into tmp */
        tmp_is_filled = *(bool *)elem;
        memcpy(tmp_key, elem + map->key_offset, ctx->key_size);
        memcpy(tmp_value, elem + map->value_offset, ctx->value_size);

        /* Copy x into map */
        *(bool *)elem = x_is_filled;
        memcpy(elem + map->key_offset, x_key, ctx->key_size);
        memcpy(elem + map->value_offset, x_value, ctx->value_size);

        if (!tmp_is_filled) {
            // Increase table size
            (*(int *)ctx->t2_ptr)++;
            // Increase total map current size
            (*(int *)ctx->map_ptr)++;

            free(x_key);
            free(x_value);
            free(tmp_key);
            free(tmp_value);
            return true;
        }

        /* Copy tmp into x */
        x_is_filled = tmp_is_filled;
        memcpy(x_key, tmp_key, ctx->key_size);
        memcpy(x_value, tmp_value, ctx->value_size);

        /* Calculate new hash */
        ctx->h1 = fasthash32(x_key, ctx->key_size, HASH_SEED_1);
    }

    free(x_key);
    free(x_value);
    free(tmp_key);
    free(tmp_value);
    return false;
}

int cuckoo_insert(const cuckoo_hashmap_t *map, const void *key_to_insert,
                  const void *value_to_insert, size_t key_size, size_t value_size,
                  cuckoo_error_t *err) {
    unsigned int step;
    void *value = NULL;
    /* First of all, let's do a couple of checks if the
     * key and values matches the  ones we expect
     */
    if (err == NULL) {
        return -1;
    }

    int ret_val = 0;
    if (map == NULL) {
        err->error_code = -1;
        strncpy(err->error_msg, "Map is NULL", CUCKOO_ERROR_MSG_SIZE);
        return -1;
    }

    if (map->key_size != key_size) {
        err->error_code = -1;
        snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                 "Key size (%ld) is not equal to the size we expect (%ld)", key_size,
                 map->key_size);
        return -1;
    }

    if (map->value_size != value_size) {
        err->error_code = -1;
        snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                 "Value size (%ld) is not equal to the size we expect (%ld)", value_size,
                 map->value_size);
        return -1;
    }

    /* Allocate memory for the entire map */
    if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
        value = malloc(roundup(map->entire_map_size, 8) * map->num_cpus);
        step = roundup(map->entire_map_size, 8);
    } else {
        value = malloc(map->entire_map_size);
        step = map->entire_map_size;
    }

    if (value == NULL) {
        err->error_code = -1;
        strncpy(err->error_msg, "Failed to allocate memory for the map", CUCKOO_ERROR_MSG_SIZE);
        return -1;
    }

    uint32_t key_map = 0;
    int ret = bpf_map_lookup_elem(map->map_fd, &key_map, value);
    if (ret) {
        err->error_code = ret;
        strncpy(err->error_msg, "Failed to lookup element", CUCKOO_ERROR_MSG_SIZE);
        free(value);
        return -1;
    }

    /* If I reach this point, the value pointer contains the entire map */
    for (int i = 0; i < map->num_cpus; i++) {
        void *base_val = value + (i * step);
        void *table1 = base_val + map->table1_offset;
        void *table2 = base_val + map->table2_offset;

        /*
         * If the element is already there, overwrite and return.
         */

        /* Now let's calculate the first hash of the key */
        uint32_t hash1 = fasthash32(key_to_insert, key_size, HASH_SEED_1);
        uint32_t idx = hash1 & (map->max_entries - 1);
        if (idx >= map->max_entries) {
            err->error_code = -1;
            snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                     "[CPU %d] Index (%d) is greater than the max entries (%d)", i, idx,
                     map->max_entries);
            free(value);
            return -1;
        }

        /* Let's get the pointer to the value we are interested */
        void *elem_with_idx = table1 + map->hash_cell_array_offset + (idx * map->hash_cell_size);
        bool elem_is_filled = *(bool *)elem_with_idx;
        void *elem_key = elem_with_idx + map->key_offset;
        void *elem_value = elem_with_idx + map->value_offset;
        if (elem_is_filled) {
            if (memcmp(key_to_insert, elem_key, map->key_size) == 0) {
                memcpy(elem_value, value_to_insert, map->value_size);
                // TODO: Better way to indicate that a specific value has been
                // updated, and not inserted for the first time?
                ret_val = 1;
                continue;
            }
        }

        /* Now let's calculate the second hash of the key */
        uint32_t hash2 = fasthash32(key_to_insert, key_size, HASH_SEED_2);
        idx = hash2 & (map->max_entries - 1);
        if (idx >= map->max_entries) {
            err->error_code = -1;
            snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                     "Index (%d) is greater than the max entries (%d)", idx, map->max_entries);
            free(value);
            return -1;
        }

        /* Let's get the pointer to the value we are interested */
        elem_with_idx = table2 + map->hash_cell_array_offset + (idx * map->hash_cell_size);
        elem_is_filled = *(bool *)elem_with_idx;
        elem_key = elem_with_idx + map->key_offset;
        elem_value = elem_with_idx + map->value_offset;
        if (elem_is_filled) {
            if (memcmp(key_to_insert, elem_key, map->key_size) == 0) {
                memcpy(elem_value, value_to_insert, map->value_size);
                ret_val = 1;
                continue;
            }
        }

        /*
         * If not, the insert the new element in the map.
         */

        loop_ctx_t ctx = {.key_to_insert = key_to_insert,
                          .value_to_insert = value_to_insert,
                          .key_size = key_size,
                          .value_size = value_size,
                          .loop_cnt = 4 + (int)(4 * LOG2(map->max_entries) / LOG2(2) + 0.5),
                          .h1 = hash1,
                          .h2 = hash2,
                          .t1_ptr = table1,
                          .t2_ptr = table2,
                          .map_ptr = base_val};

        if (!cuckoo_insert_loop(map, &ctx, err)) {
            free(value);
            return -1;
        }
    }

    /* Update the map */
    ret = bpf_map_update_elem(map->map_fd, &key_map, value, BPF_ANY);
    if (ret) {
        err->error_code = ret;
        strncpy(err->error_msg, "Failed to update element", CUCKOO_ERROR_MSG_SIZE);
        free(value);
        return -1;
    }

    free(value);
    return ret_val;
}

int cuckoo_lookup(const cuckoo_hashmap_t *map, const void *key, size_t key_size,
                  void *value_to_read, size_t value_to_read_size, bool *value_found,
                  size_t value_found_size, cuckoo_error_t *err) {
    unsigned int step;
    void *map_val;

    /* Check if err is not NULL */
    if (err == NULL) {
        return -1;
    }

    if (map == NULL) {
        err->error_code = -1;
        strncpy(err->error_msg, "Map is NULL", CUCKOO_ERROR_MSG_SIZE);
        return -1;
    }

    if (map->key_size != key_size) {
        err->error_code = -1;
        snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                 "Key size (%ld) is not equal to the size we expect (%ld)", key_size,
                 map->key_size);
        return -1;
    }

    if (value_to_read_size != (map->value_size * map->num_cpus)) {
        err->error_code = -1;
        snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                 "Value size (%ld) is not equal to the size we expect (%ld)", value_to_read_size,
                 (map->value_size * map->num_cpus));
        return -1;
    }

    if (value_found_size != (map->num_cpus * sizeof(bool))) {
        err->error_code = -1;
        snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                 "Value found size (%ld) is not equal to the size we expect (%ld)",
                 value_found_size, (map->num_cpus * sizeof(bool)));
        return -1;
    }

    /* Allocate memory for the entire map */
    if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
        map_val = malloc(roundup(map->entire_map_size, 8) * map->num_cpus);
        step = roundup(map->entire_map_size, 8);
    } else {
        map_val = malloc(map->entire_map_size);
        step = map->entire_map_size;
    }

    if (map_val == NULL) {
        err->error_code = -1;
        strncpy(err->error_msg, "Failed to allocate memory for the map", CUCKOO_ERROR_MSG_SIZE);
        free(map_val);
        return -1;
    }

    uint32_t key_map = 0;
    int ret = bpf_map_lookup_elem(map->map_fd, &key_map, map_val);
    if (ret) {
        err->error_code = ret;
        strncpy(err->error_msg, "Failed to lookup element", CUCKOO_ERROR_MSG_SIZE);
        free(map_val);
        return -1;
    }

    for (int i = 0; i < map->num_cpus; i++) {
        void *base_val = map_val + (i * step);
        void *table1 = base_val + sizeof(int);
        void *table2 = table1 + map->table_size;

        // printf("Number of entries in map on CPU %d: %d\n", i, *(int *)base_val);

        /* Now let's calculate the first hash of the key */
        uint32_t hash1 = fasthash32(key, key_size, HASH_SEED_1);
        uint32_t idx = hash1 & (map->max_entries - 1);
        if (idx >= map->max_entries) {
            err->error_code = -1;
            snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                     "Index (%d) is greater than the max entries (%d)", idx, map->max_entries);
            free(map_val);
            return -1;
        }

        /* Let's get the pointer to the value we are interested */
        void *elem_with_idx = table1 + sizeof(int) + (idx * map->hash_cell_size);
        bool elem_is_filled = *(bool *)elem_with_idx;
        void *elem_key = elem_with_idx + sizeof(bool);
        void *elem_value = elem_key + map->key_size;

        if (elem_is_filled) {
            if (memcmp(key, elem_key, map->key_size) == 0) {
                memcpy(value_to_read + (i * map->value_size), elem_value, map->value_size);
                value_found[i] = true;
                continue;
            }
        }

        /* Now let's calculate the second hash of the key */
        uint32_t hash2 = fasthash32(key, key_size, HASH_SEED_2);
        idx = hash2 & (map->max_entries - 1);
        if (idx >= map->max_entries) {
            err->error_code = -1;
            snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                     "Index (%d) is greater than the max entries (%d)", idx, map->max_entries);
            free(map_val);
            return -1;
        }

        /* Let's get the pointer to the value we are interested */
        elem_with_idx = table2 + sizeof(int) + (idx * map->hash_cell_size);
        elem_is_filled = *(bool *)elem_with_idx;
        elem_key = elem_with_idx + sizeof(bool);
        elem_value = elem_key + map->key_size;
        if (elem_is_filled) {
            if (memcmp(key, elem_key, map->key_size) == 0) {
                memcpy(value_to_read + (i * map->value_size), elem_value, map->value_size);
                value_found[i] = true;
                continue;
            }
        }

        value_found[i] = false;
    }

    free(map_val);
    return 0;
}

int cuckoo_delete(const cuckoo_hashmap_t *map, const void *key, size_t key_size,
                  cuckoo_error_t *err) {
    int ret_val = 0;
    unsigned int step;
    void *map_val;

    /* Check if err is not NULL */
    if (err == NULL) {
        return -1;
    }

    if (map == NULL) {
        err->error_code = -1;
        strncpy(err->error_msg, "Map is NULL", CUCKOO_ERROR_MSG_SIZE);
        return -1;
    }

    if (map->key_size != key_size) {
        err->error_code = -1;
        snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                 "Key size (%ld) is not equal to the size we expect (%ld)", key_size,
                 map->key_size);
        return -1;
    }

    /* Allocate memory for the entire map */
    if (map->map_type == BPF_MAP_TYPE_PERCPU_ARRAY) {
        map_val = malloc(roundup(map->entire_map_size, 8) * map->num_cpus);
        step = roundup(map->entire_map_size, 8);
    } else {
        map_val = malloc(map->entire_map_size);
        step = map->entire_map_size;
    }

    if (map_val == NULL) {
        err->error_code = -1;
        strncpy(err->error_msg, "Failed to allocate memory for the map", CUCKOO_ERROR_MSG_SIZE);
        free(map_val);
        return -1;
    }

    uint32_t key_map = 0;
    int ret = bpf_map_lookup_elem(map->map_fd, &key_map, map_val);
    if (ret) {
        err->error_code = ret;
        strncpy(err->error_msg, "Failed to lookup element", CUCKOO_ERROR_MSG_SIZE);
        free(map_val);
        return -1;
    }

    for (int i = 0; i < map->num_cpus; i++) {
        void *base_val = map_val + (i * step);
        void *table1 = base_val + sizeof(int);
        void *table2 = table1 + map->table_size;

        /* Now let's calculate the first hash of the key */
        uint32_t hash1 = fasthash32(key, key_size, HASH_SEED_1);
        uint32_t idx = hash1 & (map->max_entries - 1);
        if (idx >= map->max_entries) {
            err->error_code = -1;
            snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                     "Index (%d) is greater than the max entries (%d)", idx, map->max_entries);
            free(map_val);
            return -1;
        }

        /* Let's get the pointer to the value we are interested */
        void *elem_with_idx = table1 + sizeof(int) + (idx * map->hash_cell_size);
        bool elem_is_filled = *(bool *)elem_with_idx;
        void *elem_key = elem_with_idx + sizeof(bool);

        if (elem_is_filled) {
            if (memcmp(key, elem_key, map->key_size) == 0) {
                *(bool *)elem_with_idx = false;
                // Decrease table size
                (*(int *)table1)--;
                // Decrease total map current size
                (*(int *)base_val)--;

                ret_val = 0;
                continue;
            }
        }

        /* Now let's calculate the second hash of the key */
        uint32_t hash2 = fasthash32(key, key_size, HASH_SEED_2);
        idx = hash2 & (map->max_entries - 1);
        if (idx >= map->max_entries) {
            err->error_code = -1;
            snprintf(err->error_msg, CUCKOO_ERROR_MSG_SIZE,
                     "Index (%d) is greater than the max entries (%d)", idx, map->max_entries);
            free(map_val);
            return -1;
        }

        /* Let's get the pointer to the value we are interested */
        elem_with_idx = table2 + sizeof(int) + (idx * map->hash_cell_size);
        elem_is_filled = *(bool *)elem_with_idx;
        elem_key = elem_with_idx + sizeof(bool);

        if (elem_is_filled) {
            if (memcmp(key, elem_key, map->key_size) == 0) {
                *(bool *)elem_with_idx = false;
                // Decrease table size
                (*(int *)table2)--;
                // Decrease total map current size
                (*(int *)base_val)--;

                ret_val = 0;
                continue;
            }
        }
    }

    /* Update the map */
    ret = bpf_map_update_elem(map->map_fd, &key_map, map_val, BPF_ANY);
    if (ret) {
        err->error_code = ret;
        strncpy(err->error_msg, "Failed to update element", CUCKOO_ERROR_MSG_SIZE);
        free(map_val);
        return -1;
    }

    free(map_val);
    return ret_val;
}

void cuckoo_table_destroy(cuckoo_hashmap_t *map) {
    free(map);
}