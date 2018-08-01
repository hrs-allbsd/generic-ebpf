#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>

#include <dev/ebpf/ebpf_map.h>
#include <dev/ebpf/ebpf_map_array.h>
}

namespace {
class PercpuArrayMapLookupTest : public ::testing::Test {
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

TEST_F(PercpuArrayMapLookupTest, LookupMaxEntryPlusOne)
{
	int error;
	uint32_t key = 100;
	uint32_t value;

	error = ebpf_map_lookup_elem_from_user(eo, &key, &value);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(PercpuArrayMapLookupTest, LookupOutOfMaxEntry)
{
	int error;
	uint32_t key = 102;
	uint32_t value;

	error = ebpf_map_lookup_elem_from_user(eo, &key, &value);

	EXPECT_EQ(EINVAL, error);
}

TEST_F(PercpuArrayMapLookupTest, CorrectLookup)
{
	int error;
	uint32_t key = 50;
	uint32_t value[ebpf_ncpus()];

	error = ebpf_map_lookup_elem_from_user(eo, &key, value);

	for (uint16_t i = 0; i < ebpf_ncpus(); i++) {
		EXPECT_EQ(100, value[i]);
	}
}
} // namespace
