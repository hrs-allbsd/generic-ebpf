function postfunc(name, expr) {
}
function prefunc(name, src, dst) {
	if (name == "DIV" || name == "MOD") {
		printf("\tif (%s == 0) {\n" \
		    "\t\tebpf_error(\"division by zero at PC %%u\\n\", vm->state.pc);\n" \
		    "\t\treturn (-1);\n" \
		    "\t}\n", src);
	} else if (name == "LSH" || name == "RSH" || name == "ARSH") {
		printf("\tif (%s > sizeof(%s) * 8 - 1) {\n" \
		    "\t\t%s = 0;\n" \
		    "\t\treturn (0);\n" \
		    "\t}\n", \
		    src, dst, dst);
	}
}
function opdefine(name, type, opcode) {
	if (name == "LE")
		opcode += SRC["I"];
	if (name == "BE")
		opcode += SRC["R"];
	printf("#define\tEBPF_OP_%s%s\t0x%02x\n", name, SFX[type], opcode);
}
function opheader(name, type, opcode) {
	printf("static int ebpf_op_%s%s(%s, %s)\n{\n", \
	    name, SFX[type], \
	    "struct ebpf_vm *vm", \
	    "const struct ebpf_inst *inst");
}
function opfooter(name, type, opcode) {
	OPINIT[l++] = sprintf("\t[EBPF_OP_%s%s] = ebpf_op_%s%s,\n", \
	    name, SFX[type], name, SFX[type]);
}
function jmpop(name, type, opcode, optype, op, stype, dtype) {
	opheader(name, type, opcode);
	r = ".r64";
	sr = r;
	dr = r;
	dst = "vm->state.reg[inst->dst]" dr;
	if (type == "I") {
		src = "inst->imm";
		if (stype == "u")
			src = "(uint32_t)" src;
	}
	if (type == "R") src = "vm->state.reg[inst->src]" sr;
	if (optype == "B") {
		printf("\tif (%s %s %s) {\n", dst, op, src);
		printf("\t\tvm->state.pc += inst->offset;\n");
		printf("\t}\n");
		printf("\treturn (0);\n");
	} else if (name == "EXIT") {
		printf("\treturn(-2);\n");
	} else if (name == "CALL") {
		printf("\tif (vm->ext_funcs[(uint32_t)inst->imm] == NULL) {\n" \
		    "\t\tebpf_error(\"NULL pointer call at PC %%u\\n\", vm->state.pc);\n" \
		    "\t\treturn (-1);\n" \
		    "\t}\n"); \
		printf("\tvm->state.reg[0].r64 = vm->ext_funcs[(uint32_t)inst->imm](");
		printf("vm->state.reg[1].r64, vm->state.reg[2].r64, vm->state.reg[3].r64, ");
		printf("vm->state.reg[4].r64, vm->state.reg[5].r64");
		printf(");\n");
		printf("\treturn (0);\n");
	} else {
	}
	printf("}\n");
	opfooter(name, type, opcode);
}
function aluop(name, type, opcode, optype, op, stype, dtype) {
	opheader(name, type, opcode);
	i64 = index(name, "64");
	r = (i64) ? ".r64" : ".r32";

	sr = (stype == "u") ? r stype : r;
	dr = (dtype == "u") ? r dtype : r;

	dst = "vm->state.reg[inst->dst]" dr;
	if (type == "I") src = "inst->imm";
	if (type == "R") src = "vm->state.reg[inst->src]" sr;
	if (type == "N") src = "vm->state.reg[inst->src]" sr;

	sname = name;
	sub("64", "", sname);
	if (optype == "B") {
		prefunc(sname, src, dst);
		printf("\t%s = %s %s %s;\n", dst, dst, op, src);
		printf("\treturn (0);\n");
		postfunc(sname, dst);
	} else if (optype == "U") {
		if (sname == "MOV")
			printf("\t%s = %s %s;\n", dst, op, src);
		if (sname == "NEG")
			printf("\t%s = %s %s;\n", dst, op, dst);
		printf("\treturn (0);\n");
		postfunc(sname, dst);
	} else if (optype == "LE") {
		opcode += SRC["I"];
		dst = "vm->state.reg[inst->dst].r64";
		printf("\tif (%s == 16) {\n", src);
		printf("\t\t%s = htole16((uint16_t)%s);\n", dst, dst);
		printf("\t} else if (%s == 32) {\n", src);
		printf("\t\t%s = htole32((uint32_t)%s);\n", dst, dst);
		printf("\t} else if (%s == 64) {\n", src);
		printf("\t\t%s = htole64((uint64_t)%s);\n", dst, dst);
		printf("\t}\n");
		printf("\treturn (0);\n");
	} else if (optype == "BE") {
		opcode += SRC["R"];
		dst = "vm->state.reg[inst->dst].r64";
		printf("\tif (%s == 16) {\n", src);
		printf("\t\t%s = htobe16((uint16_t)%s);\n", dst, dst);
		printf("\t} else if (%s == 32) {\n", src);
		printf("\t\t%s = htobe32((uint32_t)%s);\n", dst, dst);
		printf("\t} else if (%s == 64) {\n", src);
		printf("\t\t%s = htobe64((uint64_t)%s);\n", dst, dst);
		printf("\t}\n");
		printf("\treturn (0);\n");
	} else {
	}
	printf("}\n");
	opfooter(name, type, opcode);
}
function ldstop(ldst, name, type, opcode, optype, op, stype, dtype) {
	opheader(name, type, opcode);

	dst = "vm->state.reg[inst->dst].r64u";
	src = "vm->state.reg[inst->src].r64u";
	if (type == "B") c = "uint8_t";
	if (type == "H") c = "uint16_t";
	if (type == "W") c = "uint32_t";
	if (type == "D") c = "uint64_t";
	if (ldst == "LD") {
		printf("\t%s = (uint32_t)inst->imm | ", dst);
		printf("((uint64_t)((inst + 1)->imm) << 32);\n");
		printf("\tvm->state.pc++;\n");
	} else if (match(ldst, "^LD")) {
		printf("\t%s = *(%s *)(uintptr_t)(%s + inst->offset);\n",
		    dst, c, src);
	} else if (match(ldst, "^STX")) {
		printf("\t*(%s *)(uintptr_t)(%s + inst->offset) = " \
		    "vm->state.reg[inst->src].r64u;\n", c, dst);
	} else if (match(ldst, "^ST")) {
		printf("\t*(%s *)(uintptr_t)(%s + inst->offset) = " \
		    "(%s)inst->imm;\n", c, dst, c);
	}
	printf("\treturn (0);\n");
	printf("}\n");
	opfooter(name, type, opcode);
}
BEGIN {
	l = 0;
	if (defineonly == 0) {
		printf("#include <sys/dev/ebpf/ebpf_internal.h>\n");
	} else {
		printf("#pragma once\n");
		printf("typedef int (*ebpf_ops_t)(%s, %s);\n", \
		    "struct ebpf_vm *", \
		    "const struct ebpf_inst *");
		printf("extern ebpf_ops_t ebpf_ops[];\n");
	}
	SFX["N"] = "";
}
END {
	if (defineonly == 0) {
		printf("ebpf_ops_t ebpf_ops[] = {\n");
		for (i = 0; i < l; i++)
			printf OPINIT[i];
		printf("};\n");
	}
}
/^#/	{ }
/^CLASS/{ CLS[$2] = $3; }
/^SRC/	{ SRC[$2] = $3; SFX[$2] = $4; }
/^SIZE/	{ SIZE[$2] = $3; SFX[$2] = $4; }
/^JMP/ || /^ALU/ {
	for (S in SRC) {
		if (index($2, S))
			if (defineonly)
				opdefine($3, S, CLS[$1] + SRC[S] + $4);
			else if (match($1, "^JMP"))
				jmpop($3, S, CLS[$1] + SRC[S] + $4, $5, $6,
				    $7, $8);
			else if (match($1, "^ALU"))
				aluop($3, S, CLS[$1] + SRC[S] + $4, $5, $6,
				    $7, $8);
	}
}
/^LD/ || /^ST/ {
	for (S in SIZE) {
		if (index($2, S))
			if (defineonly)
				opdefine($3, S, CLS[$1] + SIZE[S] + $4);
			else
				ldstop($1, $3, S, CLS[$1] + SIZE[S] + $4,
				    $5, $6, $7, $8);
	}
}
END {
}
