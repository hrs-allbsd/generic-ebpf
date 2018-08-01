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

#include <dev/ebpf/ebpf_platform.h>
#include <sys/ebpf.h>
#include <sys/ebpf_obj.h>

struct ebpf_obj *
ebpf_obj_data(ebpf_file_t *fp)
{

	if (fp == NULL || fp->f_data == NULL)
		return NULL;

	if (!is_ebpf_objfile(fp)) {
		return NULL;
	}

	return (fp->f_data);
}

void
ebpf_obj_delete(struct ebpf_obj *eo, ebpf_thread_t *td)
{

	if (eo == NULL)
		return;
	if (eo->dtor != NULL)
		(*eo->dtor)(eo, td);
	ebpf_free(eo);
}
