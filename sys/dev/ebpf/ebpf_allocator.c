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

#include <sys/ebpf.h>
#include "ebpf_allocator.h"

#define EBPF_ALLOCATOR_ALIGN sizeof(void *)

/*
 * Simple fixed size memory block allocator with free list
 * for eBPF maps. It preallocates all blocks at initialization
 * time and never calls malloc() or free() until deinitialization
 * time.
 */

static int ebpf_allocator_prealloc(ebpf_allocator_t *alloc, uint32_t nblocks,
				   int (*ctor)(void *, void *), void *arg);

int
ebpf_allocator_init(ebpf_allocator_t *alloc, uint32_t block_size,
		    uint32_t nblocks, int (*ctor)(void *, void *), void *arg)
{
	EBPF_DPRINTF("%s: enter\n", __func__);
	SLIST_INIT(&alloc->free_block);
	SLIST_INIT(&alloc->used_segment);
	alloc->nblocks = nblocks;
	alloc->block_size = block_size;
	alloc->count = nblocks;
	ebpf_mtx_spin_init(&alloc->lock, "ebpf_allocator lock");
	EBPF_DPRINTF("%s: after mtx_init\n", __func__);
	return ebpf_allocator_prealloc(alloc, nblocks, ctor, arg);
}

/*
 * Deinitialize allocator.
 *
 * Callers need to to guarantee all memory blocks are returned to the
 * allocator before calling this function.
 */
void
ebpf_allocator_deinit(ebpf_allocator_t *alloc, void (*dtor)(void *, void *),
		      void *arg)
{
	ebpf_allocator_entry_t *tmp;

	ebpf_assert(alloc->count == alloc->nblocks);

	if (dtor) {
		SLIST_FOREACH(tmp, &alloc->free_block, entry)
		{
			dtor(tmp, arg);
		}
	}

	while (!SLIST_EMPTY(&alloc->used_segment)) {
		tmp = SLIST_FIRST(&alloc->used_segment);
		if (tmp) {
			SLIST_REMOVE_HEAD(&alloc->used_segment, entry);
			ebpf_free(tmp);
		}
	}

	ebpf_mtx_destroy(&alloc->lock);
}

static int
ebpf_allocator_prealloc(ebpf_allocator_t *alloc, uint32_t nblocks,
			int (*ctor)(void *, void *), void *arg)
{
	uint32_t count = 0;
	int error = 0;

	EBPF_DPRINTF("%s: enter\n", __func__);
	while (true) {
		uint32_t size;
		uint8_t *data;
		ebpf_allocator_entry_t *segment;

		size = ebpf_getpagesize();

		if (size < sizeof(*segment) + alloc->block_size +
			       EBPF_ALLOCATOR_ALIGN) {
			size = sizeof(*segment) +
			       alloc->block_size + EBPF_ALLOCATOR_ALIGN;
		}

		data = ebpf_calloc(1, size);
		if (data == NULL) {
			return ENOMEM;
		}
		segment = (ebpf_allocator_entry_t *)data;
		SLIST_INSERT_HEAD(&alloc->used_segment, segment, entry);
		data += sizeof(*segment);
		size -= sizeof(*segment);

		uintptr_t off, mis;

		off = (uintptr_t)data;
		mis = off % EBPF_ALLOCATOR_ALIGN;
		if (mis != 0) {
			data += EBPF_ALLOCATOR_ALIGN - mis;
			size -= EBPF_ALLOCATOR_ALIGN - mis;
		}

		do {
			if (ctor) {
				error = ctor(data, arg);
				if (error) {
					return error;
				}
			}
			SLIST_INSERT_HEAD(&alloc->free_block,
					  (ebpf_allocator_entry_t *)data,
					  entry);
			data += alloc->block_size;
			size -= alloc->block_size;
			if (++count == nblocks) {
				goto finish;
			}
		} while (size > alloc->block_size);
	}

finish:
	EBPF_DPRINTF("%s: leave\n", __func__);
	return 0;
}

void *
ebpf_allocator_alloc(ebpf_allocator_t *alloc)
{
	void *ret = NULL;

	EBPF_DPRINTF("%s: enter: alloc %p count=%u\n",
	    __func__, alloc, alloc->count);
	EBPF_DPRINTF("%s: wait lock: %p\n", __func__, &alloc->lock);
	ebpf_mtx_lock_spin(&alloc->lock);
	if (alloc->count > 0) {
		ret = SLIST_FIRST(&alloc->free_block);
		SLIST_REMOVE_HEAD(&alloc->free_block, entry);
		alloc->count--;
	}
	ebpf_mtx_unlock_spin(&alloc->lock);
	EBPF_DPRINTF("%s: leave: alloc->count=%u\n", __func__, alloc->count);

	return ret;
}

void
ebpf_allocator_free(ebpf_allocator_t *alloc, void *ptr)
{
	EBPF_DPRINTF("%s: enter. wait lock: %p\n", __func__, &alloc->lock);
	ebpf_mtx_lock_spin(&alloc->lock);
	SLIST_INSERT_HEAD(&alloc->free_block, (ebpf_allocator_entry_t *)ptr,
			  entry);
	alloc->count++;
	ebpf_mtx_unlock_spin(&alloc->lock);
	EBPF_DPRINTF("%s: leave\n", __func__);
}
