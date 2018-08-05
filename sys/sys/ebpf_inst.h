/*-
 * SPDX-License-Identifier: Apache License 2.0
 *
 * Copyright 2015 Big Switch Networks, Inc
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

struct ebpf_inst {
	uint8_t opcode;
	uint8_t dst : 4;
	uint8_t src : 4;
	int16_t offset;
	int32_t imm;
};

#define EBPF_CLS_MASK 0x07
#define EBPF_CLS(op) (op & EBPF_CLS_MASK)

#define EBPF_ALU_OP_MASK 0xf0

#define EBPF_CLS_LD 0x00
#define EBPF_CLS_LDX 0x01
#define EBPF_CLS_ST 0x02
#define EBPF_CLS_STX 0x03
#define EBPF_CLS_ALU 0x04
#define EBPF_CLS_JMP 0x05
#define EBPF_CLS_ALU64 0x07

#define EBPF_SRC_IMM 0x00
#define EBPF_SRC_REG 0x08

#define EBPF_SIZE_W 0x00
#define EBPF_SIZE_H 0x08
#define EBPF_SIZE_B 0x10
#define EBPF_SIZE_DW 0x18

/* Other memory modes are not yet supported */
#define EBPF_MODE_IMM 0x00
#define EBPF_MODE_MEM 0x60

#include <sys/ebpf_vm_isa.h>
