#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_map_array.h>
}

namespace {

class PercpuArrayMapDeleteTest : public ::testing::Test {
      protected:
	struct ebpf_obj *eo;
	struct ebpf_obj_map eom;
	struct ebpf_map *m;

	virtual void
	SetUp()
	{
		int error;

		eo = (struct ebpf_obj *)&eom;
		*eo = (struct ebpf_obj){
			.type = EBPF_OBJ_TYPE_MAP,
		};
		m = EO2EMAP(eo);
		*m = (struct ebpf_map){
			.type = EBPF_MAP_TYPE_PERCPU_ARRAY,
			.key_size = sizeof(uint32_t),
			.value_size = sizeof(uint32_t),
			.max_entries = 100,
			.map_flags = 0,
		};
		uint32_t gkey = 50;
		uint32_t gval = 100;

		error = ebpf_map_init(eo);
		ASSERT_TRUE(!error);

		error = ebpf_map_update_elem_from_user(eo, &gkey, &gval, 0);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		ebpf_map_deinit(eo, NULL);
	}
};

/* Delete always failes */
TEST_F(PercpuArrayMapDeleteTest, CorrectDelete)
{
	int error;
	uint32_t key = 50;

	error = ebpf_map_delete_elem_from_user(eo, &key);

	EXPECT_EQ(EINVAL, error);
}
} // namespace
