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

#define	EO2EMHT(eo)	((struct ebpf_map_hashtable *)EO2EMAP(eo))

/*
 * hashtable_map's element. Actual value is following to
 * variable length key.
 */
struct hash_elem {
	EBPF_EPOCH_LIST_ENTRY(hash_elem) el_hash;
	uint8_t key[0];
	/* uint8_t value[value_size]; Instance of value in normal map case */
	/* uint8_t **valuep; Pointer to percpu value in percpu map case */
};

struct ebpf_map_hashtable {
	struct ebpf_map	m;
	uint32_t key_size;	/* round-up */
	uint32_t value_size;	/* round-up */
	uint32_t nbuckets;
	u_long	mht_mask;	/* size of hashtable - 1 */
	EBPF_EPOCH_LIST_HEAD(mht_hashhead, hash_elem) *mht_tbl;
	ebpf_mtx_t *mht_bucketlock;
	struct hash_elem **pcpu_extra_elems;
	ebpf_allocator_t allocator;
	ebpf_epoch_context_t ec;
};
