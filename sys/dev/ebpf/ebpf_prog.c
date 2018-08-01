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

#include "ebpf_platform.h"
#include "ebpf_prog.h"
#include "ebpf_map.h"

static void
ebpf_obj_prog_dtor(struct ebpf_obj *eo, ebpf_thread_t *td)
{
	struct ebpf_prog *ep;

	ep = EO2EPROG(eo);
	if (ep != NULL && ep->deinit != NULL)
		ep->deinit(eo, NULL);
}

static void
ebpf_prog_deinit_default(struct ebpf_obj *eo, void *arg)
{
	struct ebpf_prog *ep = EO2EPROG(eo);

	ebpf_free(ep->prog);
}

int
ebpf_prog_init(struct ebpf_obj *eo)
{
	struct ebpf_prog *ep = EO2EPROG(eo);

	if (ep == NULL ||
	    ep->type >= __EBPF_PROG_TYPE_MAX ||
	    ep->prog == NULL ||
	    ep->prog_len == 0) {
		return EINVAL;
	}

	/* ep->prog will be replaced with newly-allocated buffer. */
	struct ebpf_inst *insts = ebpf_malloc(ep->prog_len);
	if (insts == NULL) {
		return ENOMEM;
	}
	memcpy(insts, ep->prog, ep->prog_len);
	ep->prog = insts;
	ep->deinit = ebpf_prog_deinit_default;
	if (eo->dtor == NULL)
		eo->dtor = ebpf_obj_prog_dtor;

	return 0;
}

void
ebpf_prog_deinit(struct ebpf_obj *eo, void *arg)
{
	struct ebpf_prog *ep = EO2EPROG(eo);

	if (ep == NULL)
		return;
	if (ep->deinit != NULL)
		ep->deinit(eo, arg);
}
