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

#include "ebpf_dev_platform.h"
#include <dev/ebpf/ebpf_allocator.h>
#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_map_array.h>
#include <dev/ebpf/ebpf_map_hashtable.h>
#include <dev/ebpf/ebpf_prog.h>

#include <sys/ebpf.h>
#include <sys/ebpf_vm.h>
#include <sys/ebpf_inst.h>
#include <sys/ebpf_dev.h>

static void ebpf_obj_prog_dtor(struct ebpf_obj *, ebpf_thread_t *);
/*
 * Don't make functions static for now, because we want to see it by tracing
 * tools
 * like DTrace.
 *
 * TODO Make them static
 */
int ebpf_prog_mapfd_to_addr(struct ebpf_obj_prog *eop, ebpf_thread_t *td);
int ebpf_load_prog(union ebpf_req *req, ebpf_thread_t *td);
int ebpf_map_create(union ebpf_req *req, ebpf_thread_t *td);
int ebpf_ioc_map_lookup_elem(union ebpf_req *req, ebpf_thread_t *td);
int ebpf_ioc_map_update_elem(union ebpf_req *req, ebpf_thread_t *td);
int ebpf_ioc_map_delete_elem(union ebpf_req *req, ebpf_thread_t *td);
int ebpf_ioc_map_get_next_key(union ebpf_req *req, ebpf_thread_t *td);
void test_vm_attach_func(struct ebpf_vm *vm);
int ebpf_ioc_run_test(union ebpf_req *req, ebpf_thread_t *td);

static void
ebpf_obj_prog_dtor(struct ebpf_obj *eo, ebpf_thread_t *td)
{
	struct ebpf_obj_prog *eop;
	struct ebpf_prog *ep;

	eop = EO2EOP(eo);
	for (int i = 0; i < nitems(eop->attached_maps); i++) {
		if (eop->attached_maps[i]) {
			ebpf_fdrop(eop->attached_maps[i]->obj.f, td);
		}
	}
	ep = EO2EPROG(eo);
	if (ep != NULL && ep->deinit != NULL)
		ep->deinit(eo, NULL);
}

int
ebpf_prog_mapfd_to_addr(struct ebpf_obj_prog *eop, ebpf_thread_t *td)
{
	int error;
	struct ebpf_prog *ep = EO2EPROG(eop);
	struct ebpf_inst *prog = ep->prog;
	struct ebpf_inst *cur;
	uint16_t num_insts = ep->prog_len / sizeof(struct ebpf_inst);
	ebpf_file_t *f;
	struct ebpf_obj_map *eom;

	for (uint32_t i = 0; i < num_insts; i++) {
		cur = prog + i;

		if (cur->opcode != EBPF_OP_LDDW) {
			continue;
		}

		if (i == num_insts - 1 || cur[1].opcode != 0 ||
		    cur[1].dst != 0 || cur[1].src != 0 || cur[1].offset != 0) {
			error = EINVAL;
			goto err0;
		}

		// Normal lddw
		if (cur->src == 0) {
			continue;
		}

		if (cur->src != EBPF_PSEUDO_MAP_DESC) {
			error = EINVAL;
			goto err0;
		}

		error = ebpf_fget(td, cur->imm, &f);
		if (error) {
			goto err0;
		}

		eom = EO2EOM(ebpf_obj_data(f));
		if (eom == NULL) {
			error = EINVAL;
			goto err1;
		}

		if (eop->nattached_maps == nitems(eop->attached_maps)) {
			error = E2BIG;
			goto err1;
		}

		cur[0].imm = (uint32_t)eom;
		cur[1].imm = ((uint64_t)eom) >> 32;

		for (int j = 0; j < nitems(eop->attached_maps); j++) {
			if (eop->attached_maps[j]) {
				if (eop->attached_maps[j] == eom) {
					ebpf_fdrop(f, td);
					break;
				}
			} else {
				eop->attached_maps[j] = eom;
				eop->nattached_maps++;
				break;
			}
		}
		i++;
	}

	return 0;

err1:
	ebpf_fdrop(f, td);
err0:
	for (int i = 0; i < nitems(eop->attached_maps); i++) {
		if (eop->attached_maps[i]) {
			ebpf_fdrop(f, td);
			eop->attached_maps[i] = NULL;
		} else {
			break;
		}
	}

	return error;
}

int
ebpf_load_prog(union ebpf_req *req, ebpf_thread_t *td)
{
	int error;
	struct ebpf_obj *eo;
	struct ebpf_obj_prog *eop;
	struct ebpf_prog *ep;
	struct ebpf_inst *insts;

	if (req == NULL ||
	    req->prog_fdp == 0 ||
	    req->prog_type >= __EBPF_PROG_TYPE_MAX ||
	    req->prog == NULL ||
	    req->prog_len == 0 ||
	    td == NULL) {
		return EINVAL;
	}

	EBPF_DPRINTF("%s: enter\n", __func__);
	insts = ebpf_malloc(req->prog_len);
	if (insts == NULL)
		return ENOMEM;

	error = ebpf_copyin(req->prog, insts, req->prog_len);
	if (error)
		goto err0;

	EBPF_DPRINTF("%s: middle\n", __func__);
	eop = ebpf_calloc(1, sizeof(*eop));
	if (eop == NULL) {
		return ENOMEM;
		goto err0;
	}
	eop->obj = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_PROG,
		.dtor = ebpf_obj_prog_dtor,
	};
	ep = EO2EPROG(eop);
	*ep = (struct ebpf_prog){
		.type = req->prog_type,
		.prog = insts,
		.prog_len = req->prog_len,
	};
	eo = (struct ebpf_obj *)eop;
	error = ebpf_prog_init(eo);
	if (error)
		goto err1;
	/* ebpf_prog_init() allocates ep->prog. */
	ebpf_free(insts);
	insts = NULL;

	error = ebpf_prog_mapfd_to_addr(eop, td);
	if (error)
		goto err2;

	int fd;
	ebpf_file_t *f;

	error = ebpf_fopen(td, &f, &fd, eo);
	if (error)
		goto err2;
	eop->obj.f = f;

	error = ebpf_copyout(&fd, req->prog_fdp, sizeof(int));
	if (error == 0)
		return (0);
err2:
	ebpf_prog_deinit(eo, td);
err1:
	ebpf_free(eop);
err0:
	ebpf_free(insts);
	return (error);
}

int
ebpf_map_create(union ebpf_req *req, ebpf_thread_t *td)
{
	struct ebpf_obj *eo;
	struct ebpf_obj_map *eom;
	struct ebpf_map *m;
	int error;

	EBPF_DPRINTF("%s: enter req=%p, td=%p\n", __func__, req, td);
	if (!req || !req->map_fdp || !td) {
		return EINVAL;
	}

	/* Must be M_ZERO because garbage can cause a panic. */
	eom = ebpf_calloc(1, sizeof(*eom));
	if (eom == NULL) {
		return ENOMEM;
	}
	eo = (struct ebpf_obj *)eom;
	*eo = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_MAP,
	};
	m = EO2EMAP(eo);
	*m = (struct ebpf_map) {
		.type = req->map_type,
		.key_size = req->key_size,
		.value_size = req->value_size,
		.max_entries = req->max_entries,
		.map_flags = req->map_flags,
	};
	error = ebpf_map_init(eo);
	if (error) {
		ebpf_free(eom);
		return error;
	}

	int fd;
	ebpf_file_t *f;

	error = ebpf_fopen(td, &f, &fd, eo);
	if (error) {
		ebpf_map_deinit(eo, td);
		ebpf_free(eom);
		return error;
	}
	eo->f = f;

	error = ebpf_copyout(&fd, req->map_fdp, sizeof(int));
	if (error) {
		ebpf_map_deinit(eo, td);
		ebpf_free(eom);
		return error;
	}
	EBPF_DPRINTF("%s: leave req=%p, td=%p\n", __func__, req, td);

	return 0;
}

int
ebpf_ioc_map_lookup_elem(union ebpf_req *req, ebpf_thread_t *td)
{
	struct ebpf_obj *eo;
	struct ebpf_map *m;
	int error;
	ebpf_file_t *f;

	if (!req || !td || !(void *)req->key || !(void *)req->value) {
		return EINVAL;
	}

	error = ebpf_fget(td, req->map_fd, &f);
	if (error) {
		return error;
	}

	void *k, *v;
	struct ebpf_obj_map *eom = EO2EOM(ebpf_obj_data(f));
	if (eom == NULL)
		return EINVAL;
	eo = (struct ebpf_obj *)eom;
	m = EO2EMAP(eo);

	k = ebpf_malloc(m->key_size);
	if (k == NULL) {
		error = ENOMEM;
		goto err0;
	}

	error = ebpf_copyin((void *)req->key, k, m->key_size);
	if (error)
		goto err1;

	uint32_t ncpus = (m->percpu) ? ebpf_ncpus() : 1;
	v = ebpf_calloc(ncpus, m->value_size);
	if (v == NULL) {
		error = ENOMEM;
		goto err1;
	}
	error = ebpf_map_lookup_elem_from_user(eo, k, v);
	if (error) {
		goto err2;
	}

	error = ebpf_copyout(v, (void *)req->value, m->value_size * ncpus);
err2:
	ebpf_free(v);
err1:
	ebpf_free(k);
err0:
	ebpf_fdrop(f, td);
	return error;
}

int
ebpf_ioc_map_update_elem(union ebpf_req *req, ebpf_thread_t *td)
{
	struct ebpf_obj *eo;
	struct ebpf_map *m;
	int error;
	ebpf_file_t *f;

	if (!req || !td || !(void *)req->key || !(void *)req->value) {
		return EINVAL;
	}

	error = ebpf_fget(td, req->map_fd, &f);
	if (error) {
		return error;
	}

	void *k, *v;
	struct ebpf_obj_map *eom = EO2EOM(ebpf_obj_data(f));
	if (eom == NULL)
		return EINVAL;
	eo = (struct ebpf_obj *)eom;
	m = EO2EMAP(eo);

	k = ebpf_malloc(m->key_size);
	if (!k) {
		error = ENOMEM;
		goto err0;
	}

	error = ebpf_copyin((void *)req->key, k, m->key_size);
	if (error)
		goto err1;

	v = ebpf_malloc(m->value_size);
	if (!v) {
		error = ENOMEM;
		goto err1;
	}

	error = ebpf_copyin((void *)req->value, v, m->value_size);
	if (error) {
		goto err2;
	}
	error = ebpf_map_update_elem_from_user(eo, k, v, req->flags);
	if (error) {
		goto err2;
	}

	ebpf_free(k);
	ebpf_free(v);
	ebpf_fdrop(f, td);

	return 0;

err2:
	ebpf_free(v);
err1:
	ebpf_free(k);
err0:
	ebpf_fdrop(f, td);
	return error;
}

int
ebpf_ioc_map_delete_elem(union ebpf_req *req, ebpf_thread_t *td)
{
	struct ebpf_obj *eo;
	struct ebpf_map *m;
	int error;
	ebpf_file_t *f;

	if (!req || !td || !(void *)req->key) {
		return EINVAL;
	}

	error = ebpf_fget(td, req->map_fd, &f);
	if (error) {
		return error;
	}

	void *k;
	struct ebpf_obj_map *eom = EO2EOM(ebpf_obj_data(f));
	if (eom == NULL) {
		return EINVAL;
	}
	eo = (struct ebpf_obj *)eom;
	m = EO2EMAP(eo);

	k = ebpf_malloc(m->key_size);
	if (!k) {
		error = ENOMEM;
		goto err0;
	}
	error = ebpf_copyin((void *)req->key, k, m->key_size);
	if (error) {
		goto err1;
	}
	error = ebpf_map_delete_elem_from_user(eo, k);

err1:
	ebpf_free(k);
err0:
	ebpf_fdrop(f, td);
	return error;
}

int
ebpf_ioc_map_get_next_key(union ebpf_req *req, ebpf_thread_t *td)
{
	struct ebpf_obj *eo;
	struct ebpf_map *m;
	int error;
	ebpf_file_t *f;

	/*
	 * key == NULL is valid, because it means "give me a first key"
	 */
	if (!req || !td || !(void *)req->next_key) {
		return EINVAL;
	}

	error = ebpf_fget(td, req->map_fd, &f);
	if (error) {
		return error;
	}

	void *k = NULL, *nk;
	struct ebpf_obj_map *eom = EO2EOM(ebpf_obj_data(f));
	if (eom == NULL) {
		return EINVAL;
	}
	eo = (struct ebpf_obj *)eom;
	m = EO2EMAP(eo);

	if (req->key) {
		k = ebpf_malloc(m->key_size);
		if (!k) {
			error = ENOMEM;
			goto err0;
		}

		error = ebpf_copyin((void *)req->key, k, m->key_size);
		if (error) {
			goto err1;
		}
	}

	nk = ebpf_malloc(m->key_size);
	if (!nk) {
		error = ENOMEM;
		goto err1;
	}

	error = ebpf_map_get_next_key_from_user(eo, k, nk);
	if (error) {
		goto err2;
	}

	error = ebpf_copyout(nk, (void *)req->next_key, m->key_size);

err2:
	ebpf_free(nk);
err1:
	if (k) {
		ebpf_free(k);
	}
err0:
	ebpf_fdrop(f, td);
	return error;
}

void
test_vm_attach_func(struct ebpf_vm *vm)
{
	ebpf_register(vm, 1, "ebpf_map_update_elem", ebpf_map_update_elem);
	ebpf_register(vm, 2, "ebpf_map_lookup_elem", ebpf_map_lookup_elem);
	ebpf_register(vm, 3, "ebpf_map_delete_elem", ebpf_map_delete_elem);
}

int
ebpf_ioc_run_test(union ebpf_req *req, ebpf_thread_t *td)
{
	int error;
	struct ebpf_vm *vm;

	vm = ebpf_create();
	if (vm == NULL) {
		return ENOMEM;
	}
	test_vm_attach_func(vm);

	ebpf_file_t *f;
	error = ebpf_fget(td, req->prog_fd, &f);
	if (error) {
		goto err0;
	}

	struct ebpf_obj_prog *eop = EO2EOP(ebpf_obj_data(f));
	if (eop == NULL) {
		error = EINVAL;
		goto err1;
	}

	error = ebpf_load(vm, eop->prog.prog, eop->prog.prog_len);
	if (error < 0) {
		error = EINVAL;
		goto err1;
	}

	void *ctx = ebpf_calloc(req->ctx_len, 1);
	if (ctx == NULL) {
		error = ENOMEM;
		goto err1;
	}

	error = ebpf_copyin(req->ctx, ctx, req->ctx_len);
	if (error) {
		goto err2;
	}

	uint64_t result;
	if (req->jit) {
		ebpf_jit_fn fn = ebpf_compile(vm);
		if (!fn) {
			error = EINVAL;
			goto err2;
		}
		result = fn(ctx, req->ctx_len);
	} else {
		result = ebpf_exec(vm, ctx, req->ctx_len);
	}

	error = ebpf_copyout(&result, req->test_result, sizeof(uint64_t));

err2:
	ebpf_free(ctx);
err1:
	ebpf_fdrop(f, td);
err0:
	ebpf_destroy(vm);
	return error;
}

int
ebpf_ioctl(uint32_t cmd, void *data, ebpf_thread_t *td)
{
	int error;
	union ebpf_req *req = (union ebpf_req *)data;

	if (!data || !td) {
		return EINVAL;
	}

	switch (cmd) {
	case EBPFIOC_LOAD_PROG:
		error = ebpf_load_prog(req, td);
		break;
	case EBPFIOC_MAP_CREATE:
		error = ebpf_map_create(req, td);
		break;
	case EBPFIOC_MAP_LOOKUP_ELEM:
		error = ebpf_ioc_map_lookup_elem(req, td);
		break;
	case EBPFIOC_MAP_UPDATE_ELEM:
		error = ebpf_ioc_map_update_elem(req, td);
		break;
	case EBPFIOC_MAP_DELETE_ELEM:
		error = ebpf_ioc_map_delete_elem(req, td);
		break;
	case EBPFIOC_MAP_GET_NEXT_KEY:
		error = ebpf_ioc_map_get_next_key(req, td);
		break;
	case EBPFIOC_RUN_TEST:
		error = ebpf_ioc_run_test(req, td);
		break;
	default:
		error = EINVAL;
		break;
	}

	return error;
}
