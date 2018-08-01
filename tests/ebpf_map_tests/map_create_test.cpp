#include <gtest/gtest.h>

extern "C" {
#include <stdint.h>
#include <errno.h>
#include <dev/ebpf/ebpf_map.h>
}

TEST(MapCreateTest, CreateWithNULLMapPointer)
{
	int error;

	error = ebpf_map_init(NULL);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithInvalidMapType1)
{
	int error;
	struct ebpf_obj_map eom;
	struct ebpf_obj *eo;
	struct ebpf_map *m;

	eo = (struct ebpf_obj *)&eom;
	*eo = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_MAP,
	};
	m = EO2EMAP(eo);
	*m = (struct ebpf_map){
		.type = __EBPF_MAP_TYPE_MAX,
		.key_size = sizeof(uint32_t),
		.value_size =  sizeof(uint32_t),
		.max_entries = 100,
		.map_flags = 0,
	};

	error = ebpf_map_init(eo);
	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithInvalidMapType2)
{
	int error;
	struct ebpf_obj_map eom;
	struct ebpf_obj *eo;
	struct ebpf_map *m;

	eo = (struct ebpf_obj *)&eom;
	*eo = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_MAP,
	};
	m = EO2EMAP(eo);
	*m = (struct ebpf_map){
		.type = __EBPF_MAP_TYPE_MAX + 1,
		.key_size = sizeof(uint32_t),
		.value_size = sizeof(uint32_t),
		.max_entries = 100,
		.map_flags = 0,
	};
	error = ebpf_map_init(eo);

	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroKey)
{
	int error;
	struct ebpf_obj_map eom;
	struct ebpf_obj *eo;
	struct ebpf_map *m;

	eo = (struct ebpf_obj *)&eom;
	*eo = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_MAP,
	};
	m = EO2EMAP(eo);
	*m = (struct ebpf_map){
		.type = EBPF_MAP_TYPE_ARRAY,
		.key_size = 0,
		.value_size = sizeof(uint32_t),
		.max_entries = 100,
		.map_flags = 0,
	};
	error = ebpf_map_init(eo);
	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroValue)
{
	int error;
	struct ebpf_obj_map eom;
	struct ebpf_obj *eo;
	struct ebpf_map *m;

	eo = (struct ebpf_obj *)&eom;
	*eo = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_MAP,
	};
	m = EO2EMAP(eo);
	*m = (struct ebpf_map){
		.type = EBPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(uint32_t),
		.value_size = 0,
		.max_entries = 100,
		.map_flags = 0,
	};
	error = ebpf_map_init(eo);
	EXPECT_EQ(EINVAL, error);
}

TEST(MapCreateTest, CreateWithZeroMaxEntries)
{
	int error;
	struct ebpf_obj_map eom;
	struct ebpf_obj *eo;
	struct ebpf_map *m;

	eo = (struct ebpf_obj *)&eom;
	*eo = (struct ebpf_obj){
		.type = EBPF_OBJ_TYPE_MAP,
	};
	m = EO2EMAP(eo);
	*m = (struct ebpf_map){
		.type = EBPF_MAP_TYPE_ARRAY,
		.key_size = sizeof(uint32_t),
		.max_entries = 0,
		.map_flags = 0,
	};

	error = ebpf_map_init(eo);
	EXPECT_EQ(EINVAL, error);
}
