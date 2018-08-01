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

#include <dev/ebpf_dev/ebpf_dev_platform.h>
#include <sys/ebpf_dev.h>

/* Accessor for the container of an object. */
#define EO2C(eo)	(((eo) != NULL) ? (void *)&(eo)[1] : NULL)

enum ebpf_obj_type {
	EBPF_OBJ_TYPE_PROG = 0,
	EBPF_OBJ_TYPE_MAP,
	__EBPF_OBJ_TYPE_MAX
};

struct ebpf_obj {
	uint16_t type;
	ebpf_file_t *f;
	void (*dtor)(struct ebpf_obj *, ebpf_thread_t *);
};

extern struct fileops ebpf_obj_fileops;

#ifdef _KERNEL
struct ebpf_obj *ebpf_obj_data(ebpf_file_t *);
void ebpf_obj_delete(struct ebpf_obj *, ebpf_thread_t *);
#endif
