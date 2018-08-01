#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_map_hashtable.h>
}

namespace {
class HashTableMapLookupTest : public ::testing::Test {
      protected:
	struct ebpf_map *map;
	struct ebpf_map_hashtable mht;

	virtual void
	SetUp()
	{
		int error;
		map = (struct ebpf_map *)&mht;
		*map = (struct ebpf_map){
			.type = EBPF_MAP_TYPE_HASHTABLE,
			.key_size = sizeof(uint32_t),
			.value_size = sizeof(uint32_t),
			.max_entries = 100,
			.map_flags = 0,
		};
		uint32_t gkey = 50, gval = 100;

		error = ebpf_map_init(map);
		ASSERT_TRUE(!error);

		error = ebpf_map_update_elem_from_user(map, &gkey, &gval, 0);
		ASSERT_TRUE(!error);
	}

	virtual void
	TearDown()
	{
		ebpf_map_deinit(map, NULL);
	}
};

TEST_F(HashTableMapLookupTest, LookupUnexistingEntry)
{
	int error;
	uint32_t key = 51;
	void *value;

	ebpf_map_lookup_elem_from_user(map, &key, &value);

	EXPECT_EQ(NULL, value);
}

TEST_F(HashTableMapLookupTest, CorrectLookup)
{
	int error;
	uint32_t key = 50;
	uint32_t *value;

	ebpf_map_lookup_elem_from_user(map, &key, &value);

	EXPECT_NE(NULL, value);
	EXPECT_EQ(100, *(uint32_t *)value);
}
} // namespace
