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
#include "ebpf_allocator.h"
#include "ebpf_util.h"
#include "ebpf_map_hashtable.h"

/* Macros for hash access. */
/* Get a bucket index from hash. */
#define	MHTBUCKET(mht, hash)	((u_long)((hash) & (mht)->mht_mask))
/* Get a hash from key. */
#define	MHTHASH(key, len)	ebpf_jenkins_hash(key, len, 0)
/* Get a list-head of bucket from hash. */
#define	MHTHASHHEAD(mht, hash)	((mht)->mht_tbl[MHTBUCKET(mht, hash)])
/* Get the number of buckets. */
#define	NBUCKETS(mht)	((mht)->mht_mask + 1)

#define	BUCKET_LOCK_INIT(mht, i) \
	ebpf_mtx_spin_init(&mht->mht_bucketlock[i], \
	    "eBPF hashtable map bucket lock")
#define	BUCKET_LOCK_DESTROY(mht, i) \
	ebpf_mtx_destroy(&mht->mht_bucketlock[i])
#define	BUCKET_LOCK(mht, i) \
	ebpf_mtx_lock_spin(&mht->mht_bucketlock[i])
#define	BUCKET_LOCK_HASH(mht, hash) \
	BUCKET_LOCK(mht, (hash)&(mht)->mht_mask)
#define	BUCKET_UNLOCK(mht, i) \
	ebpf_mtx_unlock_spin(&mht->mht_bucketlock[i])
#define	BUCKET_UNLOCK_HASH(mht, hash) \
	BUCKET_UNLOCK(mht, (hash)&(mht)->mht_mask)

#define HASH_ELEM_VALUE(_hash_mapp, _elemp) \
	((_elemp)->key + (_hash_mapp)->key_size)
#define HASH_ELEM_PERCPU_VALUE(_hash_mapp, _elemp, _cpuid)                     \
	(*((uint8_t **)HASH_ELEM_VALUE(_hash_mapp, _elemp)) +                  \
	 (_hash_mapp)->value_size * (_cpuid))
#define HASH_ELEM_CURCPU_VALUE(_hash_mapp, _elemp)                             \
	HASH_ELEM_PERCPU_VALUE(_hash_mapp, _elemp, ebpf_curcpu())

static struct hash_elem *
get_hash_elem(struct ebpf_map_hashtable *mht, void *key)
{
	struct hash_elem *el;
	uint32_t hash = MHTHASH(key, mht->key_size);

	EBPF_EPOCH_LIST_FOREACH(el, &MHTHASHHEAD(mht, hash), el_hash) {
		if (memcmp(el->key, key, mht->key_size) == 0)
			return (el);
	}
	return (NULL);
}

static struct hash_elem *
get_extra_elem(struct ebpf_map_hashtable *mht, struct hash_elem *el)
{
	struct hash_elem *el0;

	el0 = mht->pcpu_extra_elems[ebpf_curcpu()];
	mht->pcpu_extra_elems[ebpf_curcpu()] = el;

	return (el0);
}

static int
check_update_flags(struct ebpf_map_hashtable *mht, struct hash_elem *el,
		   uint64_t flags)
{

	if (el) {
		if (flags & EBPF_NOEXIST)
			return (EEXIST);
	} else {
		if (flags & EBPF_EXIST)
			return (ENOENT);
	}

	return (0);
}

static int
percpu_elem_ctor(ebpf_allocator_entry_t *ae, struct ebpf_obj *eo)
{
	uint8_t **valuep;
	struct hash_elem *el = (struct hash_elem *)ae;
	struct ebpf_map_hashtable *mht = EO2EMHT(eo);

	ebpf_assert(mht != NULL);
	valuep = (uint8_t **)HASH_ELEM_VALUE(mht, el);
	*valuep = ebpf_calloc(ebpf_ncpus(), mht->value_size);
	if (*valuep == NULL)
		return (ENOMEM);

	return 0;
}

static void
percpu_elem_dtor(ebpf_allocator_entry_t *ae, struct ebpf_obj *eo)
{
	uint8_t **valuep;
	struct hash_elem *el = (struct hash_elem *)ae;
	struct ebpf_map_hashtable *mht = EO2EMHT(eo);

	ebpf_assert(mht != NULL);
	valuep = (uint8_t **)HASH_ELEM_VALUE(mht, el);
	ebpf_free(*valuep);
}

static bool
is_percpu(struct ebpf_map *m)
{

	return (m->type == EBPF_MAP_TYPE_PERCPU_HASHTABLE);
}

static int
hashtable_map_init(struct ebpf_obj *eo)
{
	int error;
	struct ebpf_map_hashtable *mht;
	struct ebpf_map *m;

	ebpf_assert(sizeof(*mht) <= sizeof(struct ebpf_map_storage)); 
	m = EO2EMAP(eo);
	mht = EO2EMHT(eo);

	/*
	 * Roundup key size and value size for efficiency.
	 * This affects sizeof element. Never allow users
	 * to see "padded" memory region.
	 *
	 * Here we cache the "internal" key_size and value_size.
	 * For getting the "real" key_size and value_size, please
	 * use values stored in struct ebpf_map.
	 */
	mht->key_size = ebpf_roundup(m->key_size, 8);
	mht->value_size = ebpf_roundup(m->value_size, 8);
	/* Check overflow */
	if (mht->key_size + mht->value_size + sizeof(struct hash_elem) >
	    UINT32_MAX)
		return (E2BIG);

	m->percpu = is_percpu(m);
	if (m->percpu) {
		m->elem_size = mht->key_size + sizeof(uint8_t *) +
				      sizeof(struct hash_elem);
	} else {
		m->elem_size = mht->key_size + mht->value_size +
				      sizeof(struct hash_elem);
	}

	/*
	 * Roundup number of buckets to power of two.
	 * This improbes performance, because we don't have to
	 * use slow moduro opearation.
	 */
	/*
	 * XXXHRS: nbuckets can be eliminated because hashinit(9)
	 * rounds up the number of backets by default.  NBUCKETS() macro
	 * has been added to calculate it. 
	 */
	mht->nbuckets = ebpf_roundup_pow_of_two(m->max_entries);
	mht->mht_tbl = ebpf_hashinit_flags((int)mht->nbuckets,
	    &mht->mht_mask, HASH_NOWAIT);
	if (mht->mht_tbl == NULL) {
		error = ENOMEM;
		goto err0;
	}
	mht->mht_bucketlock = ebpf_calloc(NBUCKETS(mht),
	    sizeof(*mht->mht_bucketlock));
	if (mht->mht_bucketlock == NULL) {
		error = ENOMEM;
		goto err1;
	}
	for (uint32_t i = 0; i < NBUCKETS(mht); i++)
		BUCKET_LOCK_INIT(mht, i);

	if (m->percpu) {
		mht->allocator = (ebpf_allocator_t){
			.block_size = m->elem_size,
			.nblocks = m->max_entries,
			.count = m->max_entries,
			.ctor = percpu_elem_ctor,
			.dtor = percpu_elem_dtor,
		};
	} else {
		mht->allocator = (ebpf_allocator_t){
			.block_size = m->elem_size,
			.nblocks = m->max_entries + ebpf_ncpus(),
			.count = m->max_entries + ebpf_ncpus(),
		};
	}
	error = ebpf_allocator_init(&mht->allocator, eo);
	if (error)
		goto err2;

	if (!m->percpu) {
		mht->pcpu_extra_elems =
		    ebpf_calloc(ebpf_ncpus(), sizeof(struct hash_elem *));
		if (mht->pcpu_extra_elems == NULL) {
			error = ENOMEM;
			goto err3;
		}

		/*
		 * Reserve percpu extra map element in here.
		 * These elemens are useful to update existing
		 * map element. Since updating is running at
		 * critical section, we don't require any lock
		 * to take this element.
		 */
		for (uint16_t i = 0; i < ebpf_ncpus(); i++) {
			mht->pcpu_extra_elems[i] =
			    ebpf_allocator_alloc(&mht->allocator);
			ebpf_assert(mht->pcpu_extra_elems[i]);
		}
	}
	EBPF_DPRINTF("%s: leave m=%p mht->allocator=%p "
	    "mht->allocator.count=%u\n",
	    __func__, mht, &mht->allocator, mht->allocator.count);
	return (0);

err3:
	ebpf_allocator_deinit(&mht->allocator, eo);
err2:
	for (uint32_t i = 0; i < NBUCKETS(mht); i++)
		BUCKET_LOCK_DESTROY(mht, i);
	ebpf_free(mht->mht_bucketlock);
err1:
	ebpf_hashdestroy(mht->mht_tbl, mht->mht_mask);
err0:
	return (error);
}

static void
hashtable_map_deinit(struct ebpf_obj *eo, void *arg)
{
	struct ebpf_map_hashtable *mht = EO2EMHT(eo);
	struct ebpf_map *m = EO2EMAP(eo);

	/*
	 * Wait for current readers
	 */
	ebpf_epoch_wait();

	EBPF_DPRINTF("%s: pre-percpu, mht=%p mht->alloc=%p "
	    "mht->alloc.count=%u\n",
	    __func__, mht, &mht->allocator, mht->allocator.count);

	if (!m->percpu) {
		for (uint16_t i = 0; i < ebpf_ncpus(); i++) {
			EBPF_DPRINTF("%s: alloc free cpu=%u, "
			    "mht=%p, "
			    "mht->alloc=%p, mht->alloc.count=%u\n",
			    __func__, i, mht, &mht->allocator,
			    mht->allocator.count);
			ebpf_allocator_free(&mht->allocator,
					mht->pcpu_extra_elems[i]);
		}
	}
	EBPF_DPRINTF("%s: pre-bucket free\n", __func__);

	struct hash_elem *el;
	for (uint32_t i = 0; i < NBUCKETS(mht); i++) {
		EBPF_DPRINTF("%s: bucket %u\n", __func__, i);
		while (!EBPF_EPOCH_LIST_EMPTY(&MHTHASHHEAD(mht, i))) {
			EBPF_DPRINTF("%s: free\n", __func__);
			el = EBPF_EPOCH_LIST_FIRST(&MHTHASHHEAD(mht, i),
			    struct hash_elem, el_hash);
			if (el) {
				EBPF_EPOCH_LIST_REMOVE(el, el_hash);
				EBPF_DPRINTF("%s: allocator free\n", __func__);
				ebpf_allocator_free(&mht->allocator, el);
			}
		}
	}
	ebpf_allocator_deinit(&mht->allocator, eo);

	EBPF_DPRINTF("%s: pre-mtx destroy\n", __func__);
	for (uint32_t i = 0; i < NBUCKETS(mht); i++)
		BUCKET_LOCK_DESTROY(mht, i);
	EBPF_DPRINTF("%s: pre-hash destroy\n", __func__);
	ebpf_hashdestroy(mht->mht_tbl, mht->mht_mask);
	ebpf_free(mht->mht_bucketlock);

	if (!m->percpu)
		ebpf_free(mht->pcpu_extra_elems);
}

static void *
hashtable_map_lookup_elem0(struct ebpf_obj *eo, void *key, void *value)
{
	struct ebpf_map_hashtable *mht = EO2EMHT(eo);
	struct ebpf_map *m = EO2EMAP(eo);
	struct hash_elem *elem;

	elem = get_hash_elem(mht, key);
	if (elem == NULL)
		return NULL;

	/* XXX: Use m->value_size instead of mht->value_size. */
	if (m->percpu) {
		if (value != NULL) {
			for (uint16_t i = 0; i < ebpf_ncpus(); i++) {
				EBPF_DPRINTF("%s: memcpy: %p -> %p (len=%u)\n",
				    __func__,
				    HASH_ELEM_PERCPU_VALUE(mht, elem, i),
				    (uint8_t *)value + mht->value_size * i,
				    m->value_size);
				memcpy((uint8_t *)value + mht->value_size * i,
				    HASH_ELEM_PERCPU_VALUE(mht, elem, i),
				    m->value_size);
			}
		}
		return HASH_ELEM_CURCPU_VALUE(mht, elem);
	} else {
		if (value != NULL) {
				EBPF_DPRINTF("%s: memcpy: %p -> %p (len=%u)\n",
				    __func__, HASH_ELEM_VALUE(mht, elem),
				    value, m->value_size);
			memcpy(value, HASH_ELEM_VALUE(mht, elem),
			    m->value_size);
		}
		return HASH_ELEM_VALUE(mht, elem);
	}
}
static void *
hashtable_map_lookup_elem(struct ebpf_obj *eo, void *key)
{

	return hashtable_map_lookup_elem0(eo, key, NULL);
}

static int
hashtable_map_lookup_elem_from_user(struct ebpf_obj *eo, void *key,
				    void *value)
{
	void *v;

	v = hashtable_map_lookup_elem0(eo, key, value);

	return (v == NULL) ? ENOENT : 0;
}

static int
hashtable_map_update_elem(struct ebpf_obj *eo, void *key, void *value,
			  uint64_t flags)
{
	struct ebpf_map_hashtable *mht = EO2EMHT(eo);
	struct hash_elem *old_elem, *new_elem;
	uint32_t hash = MHTHASH(key, mht->key_size);
	int error = 0;

	EBPF_DPRINTF("%s: enter %p key=%u value=%u mht->allocator.count=%u\n",
	    __func__, EO2EMAP(eo), *(uint32_t *)key, *(uint32_t *)value,
	    mht->allocator.count);
	BUCKET_LOCK_HASH(mht, hash);

	old_elem = get_hash_elem(mht, key);
	error = check_update_flags(mht, old_elem, flags);
	if (error)
		goto err0;

	if (old_elem) {
		EBPF_DPRINTF("%s: old_elem = %p\n", __func__, old_elem);
		/*
		 * In case of updating existing element, we can
		 * use percpu extra elements and swap it with old
		 * element. This avoids take lock of memory allocator.
		 */
		new_elem = get_extra_elem(mht, old_elem);
	} else {
		EBPF_DPRINTF("%s: new\n", __func__);
		new_elem = ebpf_allocator_alloc(&mht->allocator);
		if (!new_elem) {
			error = EBUSY;
			goto err0;
		}
		EBPF_DPRINTF("%s: new_elem=%p, key=%u, value=%u, bucket=%lu\n",
		    __func__, new_elem, *(uint32_t *)key,
		    *(uint32_t *)value, MHTBUCKET(mht, hash));
	}

	memcpy(new_elem->key, key, mht->key_size);
	memcpy(HASH_ELEM_VALUE(mht, new_elem), value, mht->value_size);

	EBPF_EPOCH_LIST_INSERT_HEAD(&MHTHASHHEAD(mht, hash),
	    new_elem, el_hash);
	if (old_elem)
		EBPF_EPOCH_LIST_REMOVE(old_elem, el_hash);
err0:
	BUCKET_UNLOCK_HASH(mht, hash);
	EBPF_DPRINTF("%s: leave %p key=%u value=%u\n",
	    __func__, EO2EMAP(eo), *(uint32_t *)key, *(uint32_t *)value);
	return error;
}

static int
hashtable_map_update_elem_percpu(struct ebpf_obj *eo, void *key, void *value,
				 uint64_t flags)
{
	struct ebpf_map_hashtable *mht = EO2EMHT(eo);
	struct hash_elem *old_elem, *new_elem;
	uint32_t hash = MHTHASH(key, mht->key_size);
	int error = 0;

	BUCKET_LOCK_HASH(mht, hash);

	old_elem = get_hash_elem(mht, key);
	error = check_update_flags(mht, old_elem, flags);
	if (error)
		goto err0;
	if (old_elem) {
		memcpy(HASH_ELEM_CURCPU_VALUE(mht, old_elem), value,
		       mht->value_size);
	} else {
		new_elem = ebpf_allocator_alloc(&mht->allocator);
		if (!new_elem) {
			error = EBUSY;
			goto err0;
		}

		memcpy(new_elem->key, key, mht->key_size);
		memcpy(HASH_ELEM_CURCPU_VALUE(mht, new_elem), value,
		       mht->value_size);
		EBPF_EPOCH_LIST_INSERT_HEAD(&MHTHASHHEAD(mht, hash),
		    new_elem, el_hash);
	}

err0:
	BUCKET_UNLOCK(mht, hash);
	return error;
}

static int
hashtable_map_update_elem_percpu_from_user(struct ebpf_obj *eo, void *key,
					   void *value, uint64_t flags)
{
	struct ebpf_map_hashtable *mht = EO2EMHT(eo);
	struct hash_elem *old_elem, *new_elem;
	uint32_t hash = MHTHASH(key, mht->key_size);
	int error = 0;

	BUCKET_LOCK_HASH(mht, hash);

	old_elem = get_hash_elem(mht, key);
	error = check_update_flags(mht, old_elem, flags);
	if (error)
		goto err0;

	if (old_elem) {
		for (uint16_t i = 0; i < ebpf_ncpus(); i++) {
			memcpy(HASH_ELEM_PERCPU_VALUE(mht, old_elem, i),
			       value, mht->value_size);
		}
	} else {
		new_elem = ebpf_allocator_alloc(&mht->allocator);
		if (!new_elem) {
			error = EBUSY;
			goto err0;
		}

		for (uint16_t i = 0; i < ebpf_ncpus(); i++) {
			memcpy(HASH_ELEM_PERCPU_VALUE(mht, new_elem, i),
			       value, mht->value_size);
		}

		memcpy(new_elem->key, key, mht->key_size);
		EBPF_EPOCH_LIST_INSERT_HEAD(&MHTHASHHEAD(mht, hash),
		    new_elem, el_hash);
	}

err0:
	BUCKET_UNLOCK_HASH(mht, hash);
	return error;
}

static int
hashtable_map_delete_elem(struct ebpf_obj *eo, void *key)
{
	struct ebpf_map_hashtable *mht = EO2EMHT(eo);
	struct hash_elem *elem;
	uint32_t hash = MHTHASH(key, mht->key_size);

	BUCKET_LOCK_HASH(mht, hash);

	elem = get_hash_elem(mht, key);
	if (elem)
		EBPF_EPOCH_LIST_REMOVE(elem, el_hash);

	BUCKET_UNLOCK_HASH(mht, hash);

	/*
	 * Just return element to memory allocator without any
	 * synchronization. This is safe, because ebpf_allocator
	 * never calls free().
	 */
	if (elem)
		ebpf_allocator_free(&mht->allocator, elem);

	return 0;
}

static int
hashtable_map_get_next_key(struct ebpf_obj *eo, void *key, void *next_key)
{
	struct ebpf_map_hashtable *mht = EO2EMHT(eo);
	struct hash_elem *elem, *next_elem;
	uint32_t i = 0;

	EBPF_DPRINTF("%s: enter m=%p next_key=%p\n", __func__, EO2EMAP(eo),
	    next_key); 
	if (key == NULL)
		goto get_first_key;
	EBPF_DPRINTF("%s: enter key=%u(%p)\n", __func__, *(uint32_t *)key,
	    key);

	/* Try to get the specified key.  If not exist, get smallest one. */
	uint32_t hash = MHTHASH(key, mht->key_size);
	elem = get_hash_elem(mht, key);
	EBPF_DPRINTF("%s: elem=%p\n", __func__, elem);
	if (elem == NULL)
		goto get_first_key;
	EBPF_DPRINTF("%s: bucket=%lu\n", __func__, MHTBUCKET(mht, hash));

	/* Try to get the next key.  If not, try the remaining buckets. */
	next_elem = EBPF_EPOCH_LIST_NEXT(elem, el_hash);
	EBPF_DPRINTF("%s: next_elem=%p\n", __func__, next_elem);
	if (next_elem != NULL) {
		memcpy(next_key, next_elem->key, mht->key_size);
		return 0;
	}
	i = MHTBUCKET(mht, hash) + 1;
get_first_key:
	EBPF_DPRINTF("%s: enter get_first_key i=%u/%lu \n", __func__, i,
	    NBUCKETS(mht));
	for (; i < NBUCKETS(mht); i++) {
		EBPF_DPRINTF("%s: i=%u get_first_key\n", __func__, i);
		EBPF_EPOCH_LIST_FOREACH(next_elem, &mht->mht_tbl[i], el_hash) {
			memcpy(next_key, next_elem->key, mht->key_size);
			return 0;
		}
	}
	return ENOENT;
}

struct ebpf_map_ops hashtable_map_ops = {
    .init = hashtable_map_init,
    .update_elem = hashtable_map_update_elem,
    .lookup_elem = hashtable_map_lookup_elem,
    .delete_elem = hashtable_map_delete_elem,
    .update_elem_from_user = hashtable_map_update_elem,
    .lookup_elem_from_user = hashtable_map_lookup_elem_from_user,
    .delete_elem_from_user = hashtable_map_delete_elem,
    .get_next_key_from_user = hashtable_map_get_next_key,
    .deinit = hashtable_map_deinit,
};

struct ebpf_map_ops percpu_hashtable_map_ops = {
    .init = hashtable_map_init,
    .update_elem = hashtable_map_update_elem_percpu,
    .lookup_elem = hashtable_map_lookup_elem,
    .delete_elem = hashtable_map_delete_elem,
    .update_elem_from_user = hashtable_map_update_elem_percpu_from_user,
    .lookup_elem_from_user = hashtable_map_lookup_elem_from_user,
    .delete_elem_from_user = hashtable_map_delete_elem,
    .get_next_key_from_user = hashtable_map_get_next_key,
    .deinit = hashtable_map_deinit,
};
