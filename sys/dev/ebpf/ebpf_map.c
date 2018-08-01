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

struct ebpf_map_ops *ebpf_map_ops[__EBPF_MAP_TYPE_MAX];

int
ebpf_register_map_type(uint16_t id, struct ebpf_map_ops *ops)
{

	if (id < __EBPF_MAP_TYPE_MAX && ops) {
		ebpf_map_ops[id] = ops;
		return (0);
	} else
		return (EINVAL);
}

void
ebpf_obj_map_dtor(struct ebpf_obj *eo, ebpf_thread_t *td)
{

	struct ebpf_map *m = EO2EMAP(eo);

	EBPF_DPRINTF("%s: enter eo=%p\n", __func__, eo);
	if (m == NULL || m->m_ops == NULL || m->m_ops->deinit == NULL)
		return;
	EBPF_DPRINTF("%s: enter m=%p, m->m_ops=%p, m->m_ops->deinit=%p\n",
	    __func__, m, m->m_ops, m->m_ops->deinit);
	m->m_ops->deinit(eo, NULL);
}

int
ebpf_map_init(struct ebpf_obj *eo)
{
	struct ebpf_map *m = EO2EMAP(eo);
	int error;

	if (m == NULL ||
	    m->type >= __EBPF_MAP_TYPE_MAX ||
	    m->key_size == 0 ||
	    m->value_size == 0 ||
	    m->max_entries == 0)
		return EINVAL;
	m->m_ops = ebpf_map_ops[m->type];
	eo->dtor = ebpf_obj_map_dtor;
	EBPF_DPRINTF("%s: m=%p, m->m_ops=%p\n", __func__, m, m->m_ops);

	ebpf_assert(m->m_ops->init != NULL);
	error = m->m_ops->init(eo);

	return (error);
}

void *
ebpf_map_lookup_elem(struct ebpf_obj *eo, void *key)
{
	struct ebpf_map *m = EO2EMAP(eo);

	if (m == NULL || key == NULL) {
		return NULL;
	}
	EBPF_DPRINTF("%s: m=%p\n", __func__, m);
	EBPF_DPRINTF("%s: m->m_ops=%p\n", __func__, m->m_ops);
	ebpf_assert(m->m_ops != NULL);
	EBPF_DPRINTF("%s: m->m_ops->lookup_elem=%p\n", __func__, m->m_ops);
	ebpf_assert(m->m_ops->lookup_elem != NULL);

	return m->m_ops->lookup_elem(eo, key);
}

int
ebpf_map_lookup_elem_from_user(struct ebpf_obj *eo, void *key, void *value)
{
	struct ebpf_map *m = EO2EMAP(eo);
	int error;

	if (m == NULL || key == NULL || value == NULL) {
		return EINVAL;
	}
	ebpf_assert(m->m_ops != NULL);
	ebpf_assert(m->m_ops->lookup_elem_from_user != NULL);

	ebpf_epoch_enter();
	error = m->m_ops->lookup_elem_from_user(eo, key, value);
	ebpf_epoch_exit();

	return error;
}

int
ebpf_map_update_elem(struct ebpf_obj *eo, void *key, void *value,
		     uint64_t flags)
{
	struct ebpf_map *m = EO2EMAP(eo);

	if (m == NULL || key == NULL || value == NULL || flags > EBPF_EXIST) {
		return EINVAL;
	}

	ebpf_assert(m->m_ops != NULL);
	ebpf_assert(m->m_ops->update_elem != NULL);
	return m->m_ops->update_elem(eo, key, value, flags);
}

int
ebpf_map_update_elem_from_user(struct ebpf_obj *eo, void *key, void *value,
			       uint64_t flags)
{
	struct ebpf_map *m = EO2EMAP(eo);
	int error;

	ebpf_assert(m->m_ops != NULL);
	ebpf_assert(m->m_ops->update_elem_from_user != NULL);

	ebpf_epoch_enter();
	error = m->m_ops->update_elem_from_user(eo, key, value, flags);
	ebpf_epoch_exit();

	return error;
}

int
ebpf_map_delete_elem(struct ebpf_obj *eo, void *key)
{
	struct ebpf_map *m = EO2EMAP(eo);

	if (m == NULL || key == NULL) {
		return EINVAL;
	}
	ebpf_assert(m->m_ops != NULL);
	ebpf_assert(m->m_ops->delete_elem != NULL);

	return m->m_ops->delete_elem(eo, key);
}

int
ebpf_map_delete_elem_from_user(struct ebpf_obj *eo, void *key)
{
	struct ebpf_map *m = EO2EMAP(eo);
	int error;

	if (m == NULL || key == NULL) {
		return EINVAL;
	}
	ebpf_assert(m->m_ops != NULL);
	ebpf_assert(m->m_ops->delete_elem_from_user != NULL);

	ebpf_epoch_enter();
	error = m->m_ops->delete_elem_from_user(eo, key);
	ebpf_epoch_exit();

	return error;
}

int
ebpf_map_get_next_key_from_user(struct ebpf_obj *eo, void *key, void *next_key)
{
	struct ebpf_map *m = EO2EMAP(eo);
	int error;

	/*
	 * key == NULL is valid, because it means "Give me a
	 * first key"
	 */
	if (m == NULL || next_key == NULL) {
		return EINVAL;
	}
	ebpf_assert(m->m_ops != NULL);
	ebpf_assert(m->m_ops->get_next_key_from_user != NULL);

	ebpf_epoch_enter();
	error = m->m_ops->get_next_key_from_user(eo, key, next_key);
	ebpf_epoch_exit();

	return error;
}

void
ebpf_map_deinit(struct ebpf_obj *eo, void *arg)
{
	struct ebpf_map *m = EO2EMAP(eo);

	EBPF_DPRINTF("%s: enter eo=%p\n", __func__, eo);
	if (m == NULL)
		return;
	ebpf_assert(m->m_ops != NULL);
	ebpf_assert(m->m_ops->deinit != NULL);
	m->m_ops->deinit(eo, arg);
}
