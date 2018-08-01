#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_map_array.h>
}

namespace {
class MapGetNextKeyTest : public ::testing::Test {
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
			.type = EBPF_MAP_TYPE_ARRAY,
			.key_size =  sizeof(uint32_t),
			.value_size =  sizeof(uint32_t),
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

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLMap)
{
	int error;
	uint32_t key = 50, next_key = 0;

	error = ebpf_map_get_next_key_from_user(NULL, &key, &next_key);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLKey)
{
	int error;
	uint32_t key = 50, next_key = 0;

	error = ebpf_map_get_next_key_from_user(eo, NULL, &next_key);

	EXPECT_NE(EINVAL, error);
}

TEST_F(MapGetNextKeyTest, GetNextKeyWithNULLNextKey)
{
	int error;
	uint32_t key = 50;

	error = ebpf_map_get_next_key_from_user(eo, &key, NULL);

	EXPECT_EQ(EINVAL, error);
}
} // namespace
