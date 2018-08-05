/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2015 Big Switch Networks, Inc
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
#include <sys/ebpf_vm.h>
#include <sys/ebpf_inst.h>

#define MAX_INSTS 65536
#define MAX_EXT_FUNCS 64
#define STACK_SIZE 128

struct ebpf_inst;
typedef uint64_t (*ext_func)(uint64_t, uint64_t, uint64_t,
			     uint64_t, uint64_t);
struct ebpf_vm_state {
	union {
		int64_t		r64;
		uint64_t	r64u;
		int32_t		r32;
		uint32_t	r32u;
	} reg[16];
	uint32_t	stack[(STACK_SIZE + 7) / 8];
	uint16_t	pc;
};

struct ebpf_vm {
	struct ebpf_vm_state state;
	struct ebpf_inst *insts;
	uint16_t num_insts;
	ebpf_jit_fn jitted;
	size_t jitted_size;
	ext_func ext_funcs[MAX_EXT_FUNCS];
	const char *ext_func_names[MAX_EXT_FUNCS];
};

unsigned int ebpf_lookup_registered_function(struct ebpf_vm *,
					     const char *);
bool ebpf_validate(const struct ebpf_vm *, const struct ebpf_inst *,
		   uint32_t);
