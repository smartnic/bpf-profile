/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause */
/* Copyright (c) 2023 Sebastiano Miano <mianosebastiano@gmail.com> */

#ifndef CUCKOO_USR_H
#define CUCKOO_USR_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#ifndef LIBCUCKOO_API
#define LIBCUCKOO_API __attribute__((visibility("default")))
#endif

#define CUCKOO_ERROR_MSG_SIZE 256
#define HASH_SEED_1 0x2d31e867
#define HASH_SEED_2 0x6ad611c4

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    int error_code;
    char error_msg[CUCKOO_ERROR_MSG_SIZE];
} cuckoo_error_t;

typedef struct {
    int map_fd;
    int map_id;
    int map_type;
    unsigned int num_cpus;
    size_t key_size;
    size_t value_size;
    uint32_t max_entries;
    size_t hash_cell_size;
    size_t table_size;
    size_t entire_map_size;
    size_t key_offset;
    size_t value_offset;
    size_t hash_cell_array_offset;
    size_t table1_offset;
    size_t table2_offset;
} cuckoo_hashmap_t;

/**
 * @brief **cuckoo_table_init_by_fd()** initializes the internal cuckoo hashmap object
 * to be used for all other operations.
 * @param map_fd The file descriptor of the map to be used for the hashmap.
 * @param key_size The size of the key in bytes.
 * @param value_size The size of the value in bytes.
 * @param max_entries The maximum number of entries that can be stored in the
 * hashmap.
 * @param aligned If true, we perform additional operations to align the
 * hashmap to the 4 bytes boundary. Unless you changed the definition of
 * BPF Cuckoo Hashmap in the kernel, this should be set to false.
 * @param err Pointer to a **cuckoo_error_t** object that will be populated with
 * the error code and message if the function fails.
 * @return A pointer to a **cuckoo_hashmap_t** object if the function succeeds,
 * NULL otherwise, and the error code and message will be populated in the
 * **cuckoo_error_t** object.
 */
LIBCUCKOO_API cuckoo_hashmap_t *cuckoo_table_init_by_fd(int map_fd, size_t key_size,
                                                        size_t value_size, uint32_t max_entries,
                                                        bool aligned, cuckoo_error_t *err);

/**
 * @brief **cuckoo_table_init_by_id()** initializes the internal cuckoo hashmap object
 * to be used for all other operations.
 * @param map_id The map id to be used for the hashmap. This is used to identify
 * the cuckoo hashmap in the kernel.
 * @param key_size The size of the key in bytes.
 * @param value_size The size of the value in bytes.
 * @param max_entries The maximum number of entries that can be stored in the
 * hashmap.
 * @param aligned If true, we perform additional operations to align the
 * hashmap to the 4 bytes boundary. Unless you changed the definition of
 * BPF Cuckoo Hashmap in the kernel, this should be set to false.
 * @param err Pointer to a **cuckoo_error_t** object that will be populated with
 * the error code and message if the function fails.
 * @return A pointer to a **cuckoo_hashmap_t** object if the function succeeds,
 * NULL otherwise, and the error code and message will be populated in the
 * **cuckoo_error_t** object.
 */
LIBCUCKOO_API cuckoo_hashmap_t *cuckoo_table_init_by_id(int map_id, size_t key_size,
                                                        size_t value_size, uint32_t max_entries,
                                                        bool aligned, cuckoo_error_t *err);

/**
 * @brief **cuckoo_insert()** inserts a key-value pair into the cuckoo hashmap.
 * If the key already exists, the value will be overwritten.
 * If the map type is **BPF_MAP_TYPE_PERCPU_HASH**, the value will be inserted
 * into the hashmap of the every CPU.
 * @param map Pointer to a **cuckoo_hashmap_t** object.
 * @param key Pointer to the key to be inserted.
 * @param value Pointer to the value to be inserted.
 * @param key_size The size of the key in bytes.
 * @param value_size The size of the value in bytes.
 * @param err Pointer to a **cuckoo_error_t** object that will be populated with
 * the error code and message if the function fails.
 * @return 0 if the function succeeds, -1 otherwise, and the error code and
 * message will be populated in the **cuckoo_error_t** object.
 */
LIBCUCKOO_API int cuckoo_insert(const cuckoo_hashmap_t *map, const void *key, const void *value,
                                size_t key_size, size_t value_size, cuckoo_error_t *err);

/**
 * @brief **cuckoo_lookup()** looks up a key in the cuckoo hashmap and returns
 * the value if the key exists.
 * If the map type is **BPF_MAP_TYPE_PERCPU_HASH**, the value will be read from
 * all the hashmaps of the CPUs and all the values will be copied into the
 * **value_to_read** pointer.
 * @param map Pointer to a **cuckoo_hashmap_t** object.
 * @param key Pointer to the key to be looked up.
 * @param key_size The size of the key in bytes.
 * @param value_to_read Pointer to the value to be read. The value will be
 * copied into this pointer.
 * If the map type is **BPF_MAP_TYPE_PERCPU_HASH**, the value size should be
 * **value_size * num_cpus**.
 * The caller is responsible for allocating the memory for this pointer.
 * @param value_to_read_size The size of the value to be read in bytes.
 * If the map type is **BPF_MAP_TYPE_PERCPU_HASH**, the value size should be
 * **value_size * num_cpus**.
 * @param value_found Pointer to an array of booleans that will be populated
 * with the result of the lookup.
 * @param value_found_size The size of the **value_found** array in bytes.
 * If the map type is **BPF_MAP_TYPE_PERCPU_HASH**, the value size should be
 * **sizeof(bool) * num_cpus**.
 * @param err Pointer to a **cuckoo_error_t** object that will be populated with
 * the error code and message if the function fails.
 * @return 0 if the function succeeds, -1 otherwise, and the error code and
 * message will be populated in the **cuckoo_error_t** object.
 */
LIBCUCKOO_API int cuckoo_lookup(const cuckoo_hashmap_t *map, const void *key, size_t key_size,
                                void *value_to_read, size_t value_to_read_size, bool *value_found,
                                size_t value_found_size, cuckoo_error_t *err);

/**
 * @brief **cuckoo_delete()** deletes a key-value pair from the cuckoo hashmap.
 * If the key does not exist, the function will return success.
 * If the map type is **BPF_MAP_TYPE_PERCPU_HASH**, the value will be deleted
 * from the hashmap of the every CPU.
 * @param map Pointer to a **cuckoo_hashmap_t** object.
 * @param key Pointer to the key to be deleted.
 * @param key_size The size of the key in bytes.
 * @param err Pointer to a **cuckoo_error_t** object that will be populated with
 * the error code and message if the function fails.
 * @return 0 if the function succeeds, -1 otherwise, and the error code and
 * message will be populated in the **cuckoo_error_t** object.
 */
LIBCUCKOO_API int cuckoo_delete(const cuckoo_hashmap_t *map, const void *key, size_t key_size,
                                cuckoo_error_t *err);

/**
 * @brief **cuckoo_table_destroy()** destroys the internal cuckoo hashmap object
 * and frees all the resources.
 * @param map Pointer to a **cuckoo_hashmap_t** object.
 * @return void
 */
LIBCUCKOO_API void cuckoo_table_destroy(cuckoo_hashmap_t *map);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif // CUCKOO_USR_H