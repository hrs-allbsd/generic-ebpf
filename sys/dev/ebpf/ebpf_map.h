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

#include "ebpf_platform.h"
#include <sys/ebpf.h>
#include <sys/ebpf_obj.h>

/* Accessor to ebpf_obj_map in ebpf_obj. */
#define	EO2EOM(eo)	( \
	((eo) != NULL && (eo)->type == EBPF_OBJ_TYPE_MAP) ? \
	(struct ebpf_obj_map *)(eo) : NULL)
/* Accessor to ebpf_map in ebpf_obj_map. */
#define	EO2EMAP(eo)	( \
	((eo) != NULL && (eo)->type == EBPF_OBJ_TYPE_MAP) ? \
	(struct ebpf_map *)&((struct ebpf_obj_map *)(eo))->m : NULL)
struct ebpf_map_storage {
	char __pad[128];
};
struct ebpf_obj_map {
	struct ebpf_obj obj;
	struct ebpf_map_storage m;
};
void ebpf_obj_map_dtor(struct ebpf_obj *, ebpf_thread_t *);

struct ebpf_map;

typedef int ebpf_map_init_t(struct ebpf_obj *);
typedef void *ebpf_map_lookup_elem_t(struct ebpf_obj *, void *);
typedef int ebpf_map_lookup_elem_from_user_t(struct ebpf_obj *, void *,
					     void *);
typedef int ebpf_map_update_elem_t(struct ebpf_obj *, void *, void *,
				   uint64_t);
typedef int ebpf_map_delete_elem_t(struct ebpf_obj *, void *);
typedef int ebpf_map_get_next_key_t(struct ebpf_obj *, void *,
				    void *);
typedef void ebpf_map_deinit_t(struct ebpf_obj *, void *);

struct ebpf_map_ops {
	ebpf_map_init_t *init;
	ebpf_map_lookup_elem_t *lookup_elem;
	ebpf_map_update_elem_t *update_elem;
	ebpf_map_delete_elem_t *delete_elem;
	ebpf_map_lookup_elem_from_user_t *lookup_elem_from_user;
	ebpf_map_update_elem_t *update_elem_from_user;
	ebpf_map_delete_elem_t *delete_elem_from_user;
	ebpf_map_get_next_key_t *get_next_key_from_user;
	ebpf_map_deinit_t *deinit;
};

struct ebpf_map {
	uint16_t type;
	uint32_t key_size;
	uint32_t value_size;
	uint32_t map_flags;
	uint32_t max_entries;
	bool percpu;
	struct ebpf_map_ops *m_ops;
};
int ebpf_register_map_type(uint16_t, struct ebpf_map_ops *);

ebpf_map_init_t ebpf_map_init;
ebpf_map_lookup_elem_t ebpf_map_lookup_elem;
ebpf_map_update_elem_t ebpf_map_update_elem;
ebpf_map_delete_elem_t ebpf_map_delete_elem;
ebpf_map_lookup_elem_from_user_t ebpf_map_lookup_elem_from_user;
ebpf_map_update_elem_t ebpf_map_update_elem_from_user;
ebpf_map_delete_elem_t ebpf_map_delete_elem_from_user;
ebpf_map_get_next_key_t ebpf_map_get_next_key_from_user;
/*
 * One can extend (make subclass of) struct ebpf_map and override
 * ebpf_map_deinit to manage external reference count, locking, or etc.
 */
ebpf_map_deinit_t ebpf_map_deinit;
