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
#include <sys/param.h>

#define MAX_INSTS 65536
#define MAX_EXT_FUNCS 64
#define STACK_SIZE 128

struct ebpf_inst;
struct ebpf_vm;
typedef uint64_t (*ext_func)(uint64_t, uint64_t, uint64_t,
			     uint64_t, uint64_t);
typedef uint64_t (*ebpf_jit_fn)(void *mem, size_t mem_len);
typedef int (*ebpf_ops_t)(struct ebpf_vm *, const struct ebpf_inst *);
extern ebpf_ops_t ebpf_ops[];

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
	ebpf_ops_t *ebpf_ops;
	ext_func ext_funcs[MAX_EXT_FUNCS];
	const char *ext_func_names[MAX_EXT_FUNCS];
};
unsigned int ebpf_lookup_registered_function(struct ebpf_vm *,
					     const char *);
bool ebpf_validate(const struct ebpf_vm *, const struct ebpf_inst *,
		   uint32_t);

struct ebpf_vm *ebpf_create(void);
void ebpf_destroy(struct ebpf_vm *vm);

/*
 * Register an external function
 *
 * The immediate field of a CALL instruction is an index into an array of
 * functions registered by the user. This API associates a function with
 * an index.
 *
 * 'name' should be a string with a lifetime longer than the VM.
 *
 * Returns 0 on success, -1 on error.
 */
int ebpf_register(struct ebpf_vm *vm, unsigned int idx, const char *name,
		  void *fn);

/*
 * Load program into a VM
 *
 * This must be done before calling ebpf_exec or ebpf_compile and after
 * registering all functions.
 *
 * 'prog' should point to eBPF bytecodes and 'prog_len' should be the size in
 * bytes of that buffer.
 *
 * Returns 0 on success, -1 on error.
 */
int ebpf_load(struct ebpf_vm *vm, const void *prog, uint32_t prog_len);

/*
 * Unload program from VM
 *
 * Release currently loaded bytecodes from vm.
 * Note that this function doesn't unregister external functions.
 */
void ebpf_unload(struct ebpf_vm *vm);

/*
 * Load program from an ELF binary
 *
 * This must be done before calling ebpf_exec or ebpf_compile and after
 * registering all functions.
 *
 * 'elf' should point to a copy of an ELF file in memory and 'elf_len' should
 * be the size in bytes of that buffer.
 *
 * The ELF binary must be 64-bit little-endian with a single text section
 * containing the eBPF bytecodes. This is compatible with the output of
 * Clang.
 *
 * Returns 0 on success, -1 on error.
 */
int ebpf_load_elf(struct ebpf_vm *vm, const void *elf, size_t elf_len);

uint64_t ebpf_exec(struct ebpf_vm *vm, void *mem, size_t mem_len);
uint64_t ebpf_exec_jit(const struct ebpf_vm *vm, void *mem, size_t mem_len);

ebpf_jit_fn ebpf_compile(struct ebpf_vm *vm);
