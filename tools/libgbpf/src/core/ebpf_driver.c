#include <gbpf/core/ebpf_driver.h>

int
ebpf_load_prog(EBPFDriver *driver, uint16_t prog_type, void *prog,
               uint32_t prog_len)
{
    return driver->load_prog(driver, prog_type, prog, prog_len);
}

int
ebpf_map_create(EBPFDriver *driver, uint16_t type, uint32_t key_size,
                uint32_t value_size, uint32_t max_entries, uint32_t map_flags)
{
    return driver->map_create(driver, type, key_size, value_size, max_entries,
                              map_flags);
}

int
ebpf_map_update_elem(EBPFDriver *driver, int map_desc, void *key, void *value,
                     uint64_t flags)
{
    return driver->map_update_elem(driver, map_desc, key, value, flags);
}

int
ebpf_map_lookup_elem(EBPFDriver *driver, int map_desc, void *key, void *value,
                     uint64_t flags)
{
    return driver->map_lookup_elem(driver, map_desc, key, value, flags);
}

int
ebpf_map_delete_elem(EBPFDriver *driver, int map_desc, void *key)
{
    return driver->map_delete_elem(driver, map_desc, key);
}

int
ebpf_map_get_next_key(EBPFDriver *driver, int map_desc, void *key,
                      void *next_key)
{
    return driver->map_get_next_key(driver, map_desc, key, next_key);
}

void
ebpf_close_prog_desc(EBPFDriver *driver, int prog_desc)
{
    return driver->close_prog_desc(driver, prog_desc);
}

void
ebpf_close_map_desc(EBPFDriver *driver, int map_desc)
{
    return driver->close_map_desc(driver, map_desc);
}
