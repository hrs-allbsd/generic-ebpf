#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_map_array.h>
}

namespace {
class MapUpdateTest : public ::testing::Test {
      protected:
	struct ebpf_obj *eo;
	struct ebpf_obj_map eom;
	struct ebpf_map *m;
	struct ebpf_map_array ma;

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
			.type = EBPF_MAP_TYPE_ARRAY,
			.key_size = sizeof(uint32_t),
			.value_size = sizeof(uint32_t),
			.max_entries = 100,
			.map_flags = 0,
		};

		error = ebpf_map_init(eo);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		ebpf_map_deinit(eo, NULL);
	}
};

TEST_F(MapUpdateTest, UpdateWithNULLMap)
{
	int error;
	uint32_t key = 50, value = 100;

	error = ebpf_map_update_elem(NULL, &key, &value, EBPF_ANY);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(MapUpdateTest, UpdateWithNULLKey)
{
	int error;
	uint32_t value = 100;

	error = ebpf_map_update_elem(eo, NULL, &value, EBPF_ANY);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(MapUpdateTest, UpdateWithNULLValue)
{
	int error;
	uint32_t key = 100;

	error = ebpf_map_update_elem(eo, &key, NULL, EBPF_ANY);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(MapUpdateTest, UpdateWithInvalidFlag)
{
	int error;
	uint32_t key = 1, value = 1;

	error = ebpf_map_update_elem(eo, &key, &value, EBPF_EXIST + 1);

	EXPECT_EQ(EINVAL, error);
}
} // namespace
