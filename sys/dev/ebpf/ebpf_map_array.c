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

#include "ebpf_map.h"
#include "ebpf_map_array.h"

#define MAP2EMA(m)		((struct ebpf_map_array *)(m))
#define	BASE_PTR(m)		(MAP2EMA(m)->ma.array)
#define	BASE_PTR_PERCPU0(m)	(MAP2EMA(m)->ma.parray)
#define	BASE_PTR_PERCPU(m, c)	(MAP2EMA(m)->ma.parray[c])
#define	SLOT_PTR(m, base, i)	((uint8_t *)(base) + ((m)->value_size * i))
#define	SLOT(m, i)		(((m)->value_size * i))

static void
array_map_deinit(struct ebpf_obj *eo, void *arg)
{
	struct ebpf_map *m = EO2EMAP(eo);

	EBPF_DPRINTF("%s: enter, eo=%p\n", __func__, eo);

	ebpf_epoch_wait();

	ebpf_assert(m != NULL);
	EBPF_DPRINTF("%s: free BASE_PTR(m)=%p\n", __func__, BASE_PTR(m));
	ebpf_free(BASE_PTR(m));
}

static void
array_map_deinit_percpu(struct ebpf_obj *eo, void *arg)
{
	struct ebpf_map *m = EO2EMAP(eo);

	EBPF_DPRINTF("%s: enter, eo=%p\n", __func__, eo);
	ebpf_epoch_wait();

	for (uint16_t i = 0; i < ebpf_ncpus(); i++) {
		EBPF_DPRINTF("%s: free %p (m=%p, i=%d)\n",
		    __func__, BASE_PTR_PERCPU(m, i), m, i); 
		ebpf_free(BASE_PTR_PERCPU(m, i));
	}
	ebpf_assert(m != NULL);
	EBPF_DPRINTF("%s: free %p (m=%p)\n", __func__,
	    BASE_PTR_PERCPU0(m), m); 
	ebpf_free(BASE_PTR_PERCPU0(m));
}

static int
array_map_init(struct ebpf_obj *eo)
{
	struct ebpf_map *m = EO2EMAP(eo);
	void *b;

	EBPF_DPRINTF("%s: enter, eo=%p\n", __func__, eo);
	b = ebpf_calloc(m->max_entries, m->key_size);
	if (b == NULL) {
		return ENOMEM;
	}
	BASE_PTR(m) = b;
	EBPF_DPRINTF("%s: BASE_PTR(m)=%p\n", __func__, BASE_PTR(m));
	m->percpu = false;

	return 0;
}

static int
array_map_init_percpu(struct ebpf_obj *eo)
{
	struct ebpf_map *m = EO2EMAP(eo);
	int error;
	uint16_t ncpus = ebpf_ncpus();
	uint16_t i;
	void **bp;

	bp = ebpf_calloc(ncpus, sizeof(*bp));
	if (bp == NULL)
		return (ENOMEM);
	BASE_PTR_PERCPU0(m) = bp;
	EBPF_DPRINTF("%s: alloc %p (m=%p)\n", __func__,
	    BASE_PTR_PERCPU0(m), m); 
	for (i = 0; i < ncpus; i++) {
		bp[i] = ebpf_calloc(m->max_entries, m->key_size);
		if (bp[i] == NULL) {
			error = ENOMEM;
			goto err0;
		}
		EBPF_DPRINTF("%s: alloc %p (m=%p, i=%d)\n",
		    __func__, BASE_PTR_PERCPU(m, i), m, i); 
	}
	m->percpu = true;

	return 0;

err0:
	for (uint16_t j = i; j > 0; j--)
		ebpf_free(bp[j]);
	ebpf_free(bp);

	return error;
}

static void *
array_map_lookup_elem(struct ebpf_obj *eo, void *key)
{
	struct ebpf_map *m = EO2EMAP(eo);
	uint32_t k;
	void *b;

	if (m == NULL || key == NULL)
		return (NULL);
	k = *(uint32_t *)key;
	if (k >= m->max_entries)
		return (NULL);
	if (m->percpu)
		b = BASE_PTR_PERCPU(m, ebpf_curcpu());
	else
		b = BASE_PTR(m);
	EBPF_DPRINTF("%s: slot=%u, value=%u\n", __func__,
	    *(uint32_t *)key, *(uint32_t *)SLOT_PTR(m, b, k));
	return SLOT_PTR(m, b, k);
}

static int
array_map_lookup_elem_from_user(struct ebpf_obj *eo, void *key,
    void *value)
{
	struct ebpf_map *m = EO2EMAP(eo);
	uint32_t k;
	void *elem;

	if (m == NULL || key == NULL)
		return (EINVAL);
	k = *(uint32_t *)key;
	if (k >= m->max_entries)
		return (EINVAL);
	elem = array_map_lookup_elem(eo, key);
	if (elem == NULL)
		return (ENOENT);
	if (m->percpu) {
		uint8_t *v, *v0 = (uint8_t *)value;

		for (uint16_t c = 0; c < ebpf_ncpus(); c++) {
			v = v0 + m->value_size * c;
			memcpy(v, elem, m->value_size);
		}
	} else
		memcpy(value, elem, m->value_size);

	return (0);
}

static int
array_map_lookup_elem_percpu_from_user(struct ebpf_obj *eo, void *key,
				       void *value)
{

	return array_map_lookup_elem_from_user(eo, key, value);
}

static inline int
array_map_update_check_attr(struct ebpf_obj *eo, void *key, void *value,
			    uint64_t flags)
{
	struct ebpf_map *m = EO2EMAP(eo);

	if (flags & EBPF_NOEXIST)
		return (EEXIST);

	if (*(uint32_t *)key >= m->max_entries)
		return EINVAL;

	return 0;
}

static int
array_map_update_elem0(struct ebpf_obj *eo, void *key, void *value,
    uint64_t flags, int user)
{
	struct ebpf_map *m = EO2EMAP(eo);
	int error;
	uint8_t *elem;
 
	EBPF_DPRINTF("%s: enter\n", __func__);
	error = array_map_update_check_attr(eo, key, value, flags);
	if (error)
		return error;

	if (m->percpu) {
		if (user) {
			for (uint16_t c = 0; c < ebpf_ncpus(); c++) {
				elem = SLOT_PTR(m, BASE_PTR_PERCPU(m, c),
				    *(uint32_t *)key);
				EBPF_DPRINTF("%s: memcpy value=%u, "
				    "slot=%u, dst=%p\n", __func__,
				    *(uint32_t *)value, *(uint32_t *)key,
				    elem);
				memcpy(elem, value, m->value_size);
			}
		} else  {
			elem = SLOT_PTR(m, BASE_PTR_PERCPU(m, ebpf_curcpu()),
			    *(uint32_t *)key);
			EBPF_DPRINTF("%s: memcpy value=%u, slot=%u, dst=%p\n",
			    __func__, *(uint32_t *)value, *(uint32_t *)key,
			    elem);
			memcpy(elem, value, m->value_size);
		}
	} else {
		elem = SLOT_PTR(m, BASE_PTR(m), *(uint32_t *)key);
		EBPF_DPRINTF("%s: memcpy value=%u, slot=%u, dst=%p\n",
		    __func__, *(uint32_t *)value, *(uint32_t *)key, elem);
		memcpy(elem, value, m->value_size);
	}
	EBPF_DPRINTF("%s: leave\n", __func__);

	return (0);
}

static int
array_map_update_elem(struct ebpf_obj *eo, void *key, void *value,
		      uint64_t flags)
{

	return array_map_update_elem0(eo, key, value, flags, 0);
}
static int
array_map_update_elem_percpu(struct ebpf_obj *eo, void *key, void *value,
		      uint64_t flags)
{

	return array_map_update_elem0(eo, key, value, flags, 0);
}

static int
array_map_update_elem_percpu_from_user(struct ebpf_obj *eo, void *key,
				       void *value, uint64_t flags)
{

	return array_map_update_elem0(eo, key, value, flags, 1);
}

static int
array_map_delete_elem(struct ebpf_obj *eo, void *key)
{

	return EINVAL;
}

static int
array_map_get_next_key(struct ebpf_obj *eo, void *key, void *next_key)
{
	struct ebpf_map *m = EO2EMAP(eo);
	uint32_t k = key ? *(uint32_t *)key : UINT32_MAX;
	uint32_t *nk = (uint32_t *)next_key;

	if (k >= m->max_entries) {
		*nk = 0;
		return 0;
	}

	if (k == m->max_entries - 1) {
		return ENOENT;
	}

	*nk = k + 1;
	return 0;
}

struct ebpf_map_ops array_map_ops = {
    .init = array_map_init,
    .update_elem = array_map_update_elem,
    .lookup_elem = array_map_lookup_elem,
    .delete_elem = array_map_delete_elem,
    .update_elem_from_user = array_map_update_elem,
    .lookup_elem_from_user = array_map_lookup_elem_from_user,
    .delete_elem_from_user = array_map_delete_elem,
    .get_next_key_from_user = array_map_get_next_key,
    .deinit = array_map_deinit,
};

struct ebpf_map_ops percpu_array_map_ops = {
    .init = array_map_init_percpu,
    .update_elem = array_map_update_elem_percpu,
    .lookup_elem = array_map_lookup_elem,
    .delete_elem = array_map_delete_elem, // delete is anyway invalid
    .update_elem_from_user = array_map_update_elem_percpu_from_user,
    .lookup_elem_from_user = array_map_lookup_elem_percpu_from_user,
    .delete_elem_from_user = array_map_delete_elem, // delete is anyway invalid
    .get_next_key_from_user = array_map_get_next_key,
    .deinit = array_map_deinit_percpu,
};
