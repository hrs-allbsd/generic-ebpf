#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <dev/ebpf/ebpf_prog.h>
}

TEST(ProgLoadTest, LoadWithNULLProgPointer)
{
	int error;

	error = ebpf_prog_init(NULL);
	EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithInvalidProgType1)
{
	int error;
	struct ebpf_obj *eo;
	struct ebpf_obj_prog eop;
	struct ebpf_prog *ep;
	struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

	eo = (struct ebpf_obj *)&eop;
	*eo = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_PROG,
	};
	ep = EO2EPROG(eo);
	*ep = (struct ebpf_prog){
		.type = __EBPF_PROG_TYPE_MAX,
		.prog = insts,
		.prog_len = 1, 
	};
	error = ebpf_prog_init(eo);
	EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithInvalidProgType2)
{
	int error;
	struct ebpf_obj *eo;
	struct ebpf_obj_prog eop;
	struct ebpf_prog *ep;
	struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

	eo = (struct ebpf_obj *)&eop;
	*eo = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_PROG,
	};
	ep = EO2EPROG(eo);
	*ep = (struct ebpf_prog){
		.type = __EBPF_PROG_TYPE_MAX + 1,
		.prog = insts,
		.prog_len = 1, 
	};
	error = ebpf_prog_init(eo);
	EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithZeroLen)
{
	int error;
	struct ebpf_obj *eo;
	struct ebpf_obj_prog eop;
	struct ebpf_prog *ep;
	struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

	eo = (struct ebpf_obj *)&eop;
	*eo = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_PROG,
	};
	ep = EO2EPROG(eo);
	*ep = (struct ebpf_prog){
		.type = EBPF_PROG_TYPE_TEST,
		.prog = insts,
		.prog_len = 0, 
	};
	error = ebpf_prog_init(eo);
	EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, LoadWithNULLProg)
{
	int error;
	struct ebpf_obj *eo;
	struct ebpf_obj_prog eop;
	struct ebpf_prog *ep;
	struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

	eo = (struct ebpf_obj *)&eop;
	*eo = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_PROG,
	};
	ep = EO2EPROG(eo);
	*ep = (struct ebpf_prog){
		.type = EBPF_PROG_TYPE_TEST,
		.prog = NULL,
		.prog_len = 1, 
	};
	error = ebpf_prog_init(eo);
	EXPECT_EQ(EINVAL, error);
}

TEST(ProgLoadTest, CorrectLoad)
{
	int error;
	struct ebpf_obj *eo;
	struct ebpf_obj_prog eop;
	struct ebpf_prog *ep;
	struct ebpf_inst insts[] = {{EBPF_OP_EXIT, 0, 0, 0, 0}};

	eo = (struct ebpf_obj *)&eop;
	*eo = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_PROG,
	};
	ep = EO2EPROG(eo);
	*ep = (struct ebpf_prog){
		.type = EBPF_PROG_TYPE_TEST,
		.prog = insts,
		.prog_len = 1, 
	};
	error = ebpf_prog_init(eo);
	EXPECT_EQ(0, error);

	ebpf_prog_deinit(eo, NULL);
}
