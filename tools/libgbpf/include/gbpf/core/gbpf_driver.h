/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2017-2018 Yutaro Hayakawa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <stdint.h>

struct gbpf_driver;
typedef struct gbpf_driver GBPFDriver;

typedef int(gbpf_load_prog_t)(GBPFDriver *self, uint16_t prog_type, void *prog,
			      uint32_t prog_len);
typedef int(gbpf_map_create_t)(GBPFDriver *self, uint16_t type,
			       uint32_t key_size, uint32_t value_size,
			       uint32_t max_entries, uint32_t map_flags);
typedef int(gbpf_map_update_elem_t)(GBPFDriver *self, int map_desc, void *key,
				    void *value, uint64_t flags);
typedef int(gbpf_map_lookup_elem_t)(GBPFDriver *self, int map_desc, void *key,
				    void *value);
typedef int(gbpf_map_delete_elem_t)(GBPFDriver *self, int map_desc, void *key);
typedef int(gbpf_map_get_next_key_t)(GBPFDriver *self, int map_desc, void *key,
				     void *next_key);
typedef void(gbpf_close_prog_desc_t)(GBPFDriver *self, int prog_desc);
typedef void(gbpf_close_map_desc_t)(GBPFDriver *self, int map_desc);

struct gbpf_driver {
	gbpf_load_prog_t *load_prog;
	gbpf_map_create_t *map_create;
	gbpf_map_update_elem_t *map_update_elem;
	gbpf_map_lookup_elem_t *map_lookup_elem;
	gbpf_map_delete_elem_t *map_delete_elem;
	gbpf_map_get_next_key_t *map_get_next_key;
	gbpf_close_prog_desc_t *close_prog_desc;
	gbpf_close_map_desc_t *close_map_desc;
};

gbpf_load_prog_t gbpf_load_prog;
gbpf_map_create_t gbpf_map_create;
gbpf_map_update_elem_t gbpf_map_update_elem;
gbpf_map_lookup_elem_t gbpf_map_lookup_elem;
gbpf_map_delete_elem_t gbpf_map_delete_elem;
gbpf_map_get_next_key_t gbpf_map_get_next_key;
gbpf_close_prog_desc_t gbpf_close_prog_desc;
gbpf_close_map_desc_t gbpf_close_map_desc;
