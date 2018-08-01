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

struct fileops ebpf_obj_fileops;

static bool
is_ebpf_objfile(ebpf_file_t *fp)
{
	if (fp == NULL)
		return false;

	return (fp->f_ops == &ebpf_obj_fileops);
}

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

/*
 * Extend badfileops for anonimous file for ebpf objects.
 */
static int
ebpf_obj_fo_close(struct file *fp, struct thread *td)
{
	struct ebpf_obj *eo;

	ebpf_assert(fp != NULL);

	eo = fp->f_data;
	EBPF_DPRINTF("%s: fp=%p, fp->f_data=%p, fp->f_count=%d\n",
	    __func__, fp, fp->f_data, fp->f_count);
	if (fp->f_count == 0)
		ebpf_obj_delete(eo, td);

        return 0;
}

static void
ebpf_obj_fileops_init(void *data)
{
	/*
	 * File operation definition for ebpf object file.
	 * It simply check reference count on file close
	 * and execute destractor of the ebpf object if
	 * the reference count was 0. It doesn't allow to
	 * perform any file operations except close(2)
	 */
	memcpy(&ebpf_obj_fileops, &badfileops, sizeof(ebpf_obj_fileops));
	ebpf_obj_fileops.fo_close = ebpf_obj_fo_close;
}
SYSINIT(ebpf_fileops, SI_SUB_KLD, SI_ORDER_ANY, ebpf_obj_fileops_init, NULL);
