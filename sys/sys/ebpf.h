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

#pragma once

#define __EBPF_MAP_TYPE_MAX 256
#define __EBPF_PROG_TYPE_MAX 256

enum ebpf_basic_map_types {
	EBPF_MAP_TYPE_BAD = 0,
	EBPF_MAP_TYPE_ARRAY,
	EBPF_MAP_TYPE_PERCPU_ARRAY,
	EBPF_MAP_TYPE_HASHTABLE,
	EBPF_MAP_TYPE_PERCPU_HASHTABLE,
	__EBPF_BASIC_MAP_TYPE_MAX
};

enum ebpf_basic_prog_types { EBPF_PROG_TYPE_TEST, __EBPF_BASIC_PROG_TYPE_MAX };

enum ebpf_map_update_flags {
	EBPF_ANY = 0,
	EBPF_NOEXIST,
	EBPF_EXIST,
	__EBPF_MAP_UPDATE_FLAGS_MAX
};

#define EBPF_PSEUDO_MAP_DESC 1
#define EBPF_PROG_MAX_ATTACHED_MAPS 64

#ifndef DEBUG_VERBOSE
#define	EBPF_DPRINTF(...)
#define	EBPF_DPRINTF0(...)
#else
#define	EBPF_DPRINTF(...)
	do {					\
		printf(__VA_ARGS__);		\
	} while(0)
#define	EBPF_DPRINTF0(v, ...)
	do {					\
		if ((v) < DEBUG_VERBOSE)	\
			printf(__VA_ARGS__);	\
	} while(0)
#endif
