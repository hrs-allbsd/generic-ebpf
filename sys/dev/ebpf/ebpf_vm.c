/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2018 Yutaro Hayakawa
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

#include <sys/param.h>

#include "ebpf_platform.h"
#include "ebpf_internal.h"
#include <sys/ebpf_vm_isa.h>

struct ebpf_vm *
ebpf_create(void)
{
	struct ebpf_vm *vm = ebpf_calloc(1, sizeof(*vm));

	return (vm);
}

void
ebpf_destroy(struct ebpf_vm *vm)
{
	if (vm == NULL)
		return;

	ebpf_exfree(vm->jitted, vm->jitted_size);
	ebpf_free(vm->insts);
	ebpf_free(vm);
}

int
ebpf_register(struct ebpf_vm *vm, unsigned int idx, const char *name, void *fn)
{
	if (vm == NULL ||
	    idx >= MAX_EXT_FUNCS ||
	    name == NULL ||
	    fn == NULL )
		return -1;

	EBPF_DPRINTF("%s: ext_funcs[%d] = %p\n", __func__, idx, fn);
	vm->ext_funcs[idx] = (ext_func)fn;
	EBPF_DPRINTF("%s: ext_func_names[%d] = %s\n", __func__, idx, name);
	vm->ext_func_names[idx] = name;
	return 0;
}

unsigned int
ebpf_lookup_registered_function(struct ebpf_vm *vm, const char *name)
{
	if (vm == NULL || name == NULL)
		return -1;
	for (int i = 0; i < nitems(vm->ext_funcs); i++) {
		const char *other = vm->ext_func_names[i];

		if (other && !strcmp(other, name)) {
			return i;
		}
	}

	return -1;
}

int
ebpf_load(struct ebpf_vm *vm, const void *prog, uint32_t prog_len)
{
	if (!vm || !prog || prog_len == 0) {
		return -1;
	}

	if (prog_len % sizeof(struct ebpf_inst) != 0) {
		ebpf_error("prog_len must be a multiple of 8\n");
		return -1;
	}

	if (!ebpf_validate(vm, prog, prog_len / sizeof(struct ebpf_inst))) {
		return -1;
	}

	if (vm != NULL)
		ebpf_unload(vm);
	vm->insts = ebpf_malloc(prog_len);
	if (vm->insts == NULL) {
		ebpf_error("out of memory\n");
		return -1;
	}

	memcpy(vm->insts, prog, prog_len);
	vm->num_insts = prog_len / sizeof(struct ebpf_inst);

	return 0;
}

void
ebpf_unload(struct ebpf_vm *vm)
{
	ebpf_assert(vm != NULL);

	ebpf_exfree(vm->jitted, vm->jitted_size);
	vm->jitted = NULL;
	vm->jitted_size = 0;
	ebpf_free(vm->insts);
	vm->insts = NULL;
	memset(&vm->state, 0, sizeof(vm->state));
}

#ifdef _KERNEL
uint64_t
ebpf_exec(struct ebpf_vm *vm, void *mem, size_t mem_len)
{
	int ret;

	EBPF_DPRINTF("%s: enter\n", __func__);
	if (vm == NULL)
		return (UINT64_MAX);
	if (vm->insts == NULL) {
		/* Code must be loaded before we can execute */
		return UINT64_MAX;
	}
	vm->state.pc = 0;
	EBPF_DPRINTF("\tvm=%p\n", vm);
	EBPF_DPRINTF("\tvm->insts=%p\n", vm);
	EBPF_DPRINTF("\tmem=%p, mem_len=%zu\n", mem, mem_len);
#ifdef DEBUG_VERBOSE
	for (int i = 0; i < nitems(vm->ext_funcs); i++) {
		EBPF_DPRINTF("%s: ext_func_names[%d] = %s,\n",
		    __func__, i, vm->ext_func_names[i]);
	}
#endif
	vm->state.reg[1].r64u  = (uintptr_t)mem;
	vm->state.reg[10].r64u = (uintptr_t)vm->state.stack + 
	    sizeof(vm->state.stack);
	ret = 0;
	do {
		EBPF_DPRINTF("%s: pc=%d, inst=0x%02x, "
		    "offset=0x%04x, imm=0x%08x\n", __func__,
		    vm->state.pc, vm->insts[vm->state.pc].opcode,
		    vm->insts[vm->state.pc].offset,
		    vm->insts[vm->state.pc].imm);
#ifdef DEBUG_VERBOSE
		for (int i = 0; i < 16; i++) {
			EBPF_DPRINTF("%s:\treg[%d].r64u=%016lx\n", __func__,
			    i, vm->state.reg[i].r64u);
		}
#endif
		ret = ebpf_ops[vm->insts[vm->state.pc].opcode](vm,
		    &vm->insts[vm->state.pc]);
		EBPF_DPRINTF("%s: ret=%d\n", __func__, ret);
		vm->state.pc++;
	} while (ret == 0);

		EBPF_DPRINTF("%s: EXIT\n", __func__);
#ifdef DEBUG_VERBOSE
		for (int i = 0; i < 16; i++) {
			EBPF_DPRINTF("%s:\treg[%d].r64u=%016lx\n", __func__,
			    i, vm->state.reg[i].r64u);
		}
#endif
	return (vm->state.reg[0].r64u);
}

uint64_t
ebpf_exec_jit(const struct ebpf_vm *vm, void *mem, size_t mem_len)
{
	EBPF_DPRINTF("%s: enter\n", __func__);
	if (!vm) {
		return UINT64_MAX;
	}

	if (vm->jitted) {
		return vm->jitted(mem, mem_len);
	} else {
		return UINT64_MAX;
	}
	EBPF_DPRINTF("%s: leave\n", __func__);
}
#endif
