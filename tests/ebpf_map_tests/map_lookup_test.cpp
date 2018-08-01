#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
}

namespace {
class MapLookupTest : public ::testing::Test {
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

TEST_F(MapLookupTest, LookupWithNULLMap)
{
	int error;
	uint32_t key = 50;
	void *value;

	value = ebpf_map_lookup_elem(NULL, (void *)&key);

	EXPECT_EQ(NULL, value);
}

TEST_F(MapLookupTest, LookupWithNULLKey)
{
	int error;
	void *value;

	value = ebpf_map_lookup_elem(eo, NULL);

	EXPECT_EQ(NULL, value);
}

TEST_F(MapLookupTest, LookupWithNULLValue)
{
	int error;
	uint32_t key = 100;
	void *value;

	value = ebpf_map_lookup_elem(eo, (void *)&key);

	EXPECT_EQ(NULL, value);
}
} // namespace
