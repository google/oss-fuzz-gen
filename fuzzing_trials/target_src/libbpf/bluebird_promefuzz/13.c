#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "libbpf.h"

// Define a minimal bpf_map_def for initialization
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

enum libbpf_map_type {
    LIBBPF_MAP_UNSPEC,
    LIBBPF_MAP_DATA,
    LIBBPF_MAP_BSS,
    LIBBPF_MAP_RODATA,
    LIBBPF_MAP_KCONFIG,
};

struct bpf_object {
    char name[16];
    char license[64];
    __u32 kern_version;
    struct bpf_map *maps;
    size_t nr_maps;
    size_t maps_cap;
};

struct bpf_map {
    struct bpf_object *obj;
    char *name;
    char *real_name;
    int fd;
    int sec_idx;
    size_t sec_offset;
    int map_ifindex;
    int inner_map_fd;
    struct bpf_map_def def;
    __u32 numa_node;
    __u32 btf_var_idx;
    int mod_btf_fd;
    __u32 btf_key_type_id;
    __u32 btf_value_type_id;
    __u32 btf_vmlinux_value_type_id;
    enum libbpf_map_type libbpf_type;
    void *mmaped;
    struct bpf_struct_ops *st_ops;
    struct bpf_map *inner_map;
    void **init_slots;
    int init_slots_sz;
    char *pin_path;
    bool pinned;
    bool reused;
    bool autocreate;
    bool autoattach;
    __u64 map_extra;
    struct bpf_program *excl_prog;
};

static void initialize_bpf_map(struct bpf_map *map, struct bpf_object *obj) {
    memset(map, 0, sizeof(struct bpf_map));
    map->obj = obj;
    map->def.key_size = sizeof(uint32_t);
    map->def.value_size = sizeof(uint32_t);
    map->def.max_entries = 10;
    map->fd = -1;  // Uninitialized state
}

int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(uint32_t)) {
        return 0; // Not enough data to proceed
    }

    struct bpf_object obj;
    memset(&obj, 0, sizeof(struct bpf_object));
    obj.nr_maps = 1;

    struct bpf_map map;
    initialize_bpf_map(&map, &obj);

    // Use the first byte as a potential NUMA node
    __u32 numa_node = Data[0];

    // Call bpf_map__set_numa_node
    int ret = bpf_map__set_numa_node(&map, numa_node);
    if (ret != 0 && ret != -EBUSY) {
        fprintf(stderr, "Error setting NUMA node: %d\n", ret);
    }

    // Call bpf_map__max_entries
    __u32 max_entries = bpf_map__max_entries(&map);
    if (max_entries != map.def.max_entries) {
        fprintf(stderr, "Unexpected max_entries: %u\n", max_entries);
    }

    // Prepare key and value for update, lookup, and delete operations
    uint32_t key = 0;
    uint32_t value = 0;
    size_t key_sz = sizeof(key);
    size_t value_sz = sizeof(value);
    __u64 flags = 0;

    // Call bpf_map__update_elem
    ret = bpf_map__update_elem(&map, &key, key_sz, &value, value_sz, flags);
    if (ret != 0) {
        fprintf(stderr, "Error updating element: %d\n", ret);
    }

    // Call bpf_map__get_next_key
    uint32_t next_key;
    ret = bpf_map__get_next_key(&map, NULL, &next_key, key_sz);
    if (ret != 0 && ret != -ENOENT) {
        fprintf(stderr, "Error getting next key: %d\n", ret);
    }

    // Call bpf_map__delete_elem
    ret = bpf_map__delete_elem(&map, &key, key_sz, flags);
    if (ret != 0) {
        fprintf(stderr, "Error deleting element: %d\n", ret);
    }

    // Call bpf_map__lookup_and_delete_elem
    ret = bpf_map__lookup_and_delete_elem(&map, &key, key_sz, &value, value_sz, flags);
    if (ret != 0) {
        fprintf(stderr, "Error looking up and deleting element: %d\n", ret);
    }

    return 0;
}
#ifdef INC_MAIN
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
int main(int argc, char *argv[])
{
    FILE *f;
    uint8_t *data = NULL;
    long size;

    if(argc < 2)
        exit(0);

    f = fopen(argv[1], "rb");
    if(f == NULL)
        exit(0);

    fseek(f, 0, SEEK_END);

    size = ftell(f);
    rewind(f);

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_13(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
