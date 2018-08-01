#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_map_array.h>
}

namespace {
class ArrayMapGetNextKeyTest : public ::testing::Test {
      protected:
	struct ebpf_obj *eo;
	struct ebpf_obj_map eom;
	struct ebpf_map *m;

	virtual void
	SetUp()
	{
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
		int error = ebpf_map_init(eo);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		ebpf_map_deinit(eo, NULL);
	}
};

TEST_F(ArrayMapGetNextKeyTest, GetNextKeyWithMaxKey)
{
	int error;
	uint32_t key = 99, next_key = 0;

	error = ebpf_map_get_next_key_from_user(eo, &key, &next_key);

	EXPECT_EQ(0, next_key);
}

TEST_F(ArrayMapGetNextKeyTest, GetFirstKey)
{
	int error;
	uint32_t next_key = 0;

	error = ebpf_map_get_next_key_from_user(eo, NULL, &next_key);

	EXPECT_EQ(0, next_key);
}

TEST_F(ArrayMapGetNextKeyTest, CorrectGetNextKey)
{
	int error;
	uint32_t key = 50, next_key = 0;

	error = ebpf_map_get_next_key_from_user(eo, &key, &next_key);

	EXPECT_EQ(51, next_key);
}
} // namespace
