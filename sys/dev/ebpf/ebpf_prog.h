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

#include <sys/ebpf.h>
#include <sys/ebpf_obj.h>

struct ebpf_inst;

struct ebpf_prog {
	uint16_t type;
	struct ebpf_inst *prog;
	uint32_t prog_len;
	void (*deinit)(struct ebpf_obj *, void *);
};

int ebpf_prog_init(struct ebpf_obj *);
void ebpf_prog_deinit(struct ebpf_obj *, void *);

/* Accessor to ebpf_prog in ebpf_obj. */
#define EO2EPROG(eo)	( \
	((eo) != NULL) ? \
	(struct ebpf_prog *)&((struct ebpf_obj_prog *)(eo))->prog : NULL)
/* Accessor to ebpf_obj_prog in ebpf_obj. */
#define	EO2EOP(eo) (((eo) != NULL && (eo)->type == EBPF_OBJ_TYPE_PROG) ? \
	(struct ebpf_obj_prog *)(eo) : NULL)

#define EBPF_OBJ_PROG_MAX_ATTACHED_MAPS EBPF_DEV_PROG_MAX_ATTACHED_MAPS
struct ebpf_obj_prog {
	struct ebpf_obj obj;
	struct ebpf_prog prog;
	struct ebpf_obj_map *attached_maps[EBPF_PROG_MAX_ATTACHED_MAPS];
	uint16_t nattached_maps;
};
