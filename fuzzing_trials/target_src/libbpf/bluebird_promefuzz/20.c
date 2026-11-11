#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libbpf.h"

struct bpf_map {
    struct bpf_object *obj;
    char *name;
    char *real_name;
    int fd;
    int sec_idx;
    size_t sec_offset;
    int map_ifindex;
    int inner_map_fd;
    struct bpf_map_def {
        unsigned int type;
        unsigned int key_size;
        unsigned int value_size;
        unsigned int max_entries;
        unsigned int map_flags;
    } def;
    __u32 numa_node;
    __u32 btf_var_idx;
    int mod_btf_fd;
    __u32 btf_key_type_id;
    __u32 btf_value_type_id;
    __u32 btf_vmlinux_value_type_id;
    enum libbpf_map_type {
        LIBBPF_MAP_UNSPEC,
        LIBBPF_MAP_DATA,
        LIBBPF_MAP_BSS,
        LIBBPF_MAP_RODATA,
        LIBBPF_MAP_KCONFIG,
    } libbpf_type;
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

static struct bpf_map *create_dummy_bpf_map() {
    struct bpf_map *map = (struct bpf_map *)calloc(1, sizeof(struct bpf_map));
    if (!map) return NULL;

    map->name = strdup("dummy_map");
    map->real_name = strdup(".dummy_map");
    map->fd = -1;
    map->sec_idx = 0;
    map->sec_offset = 0;
    map->map_ifindex = 0;
    map->inner_map_fd = -1;
    map->def.type = BPF_MAP_TYPE_HASH;
    map->def.key_size = 4;
    map->def.value_size = 8;
    map->def.max_entries = 1024;
    map->def.map_flags = 0;
    map->numa_node = 0;
    map->btf_var_idx = 0;
    map->mod_btf_fd = -1;
    map->btf_key_type_id = 0;
    map->btf_value_type_id = 0;
    map->btf_vmlinux_value_type_id = 0;
    map->libbpf_type = LIBBPF_MAP_UNSPEC;
    map->pinned = false;
    map->reused = false;
    map->autocreate = false;
    map->autoattach = false;
    map->map_extra = 0;
    return map;
}

static void cleanup_dummy_bpf_map(struct bpf_map *map) {
    if (!map) return;
    free(map->name);
    free(map->real_name);
    free(map);
}

int LLVMFuzzerTestOneInput_20(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct bpf_map)) return 0;

    struct bpf_map *map = create_dummy_bpf_map();
    if (!map) return 0;

    // Optionally modify map fields based on input data
    if (Size >= sizeof(int)) {
        map->map_ifindex = *(int *)Data;
    }
    if (Size >= sizeof(int) * 2) {
        map->def.key_size = *(unsigned int *)(Data + sizeof(int));
    }
    if (Size >= sizeof(int) * 3) {
        map->def.value_size = *(unsigned int *)(Data + sizeof(int) * 2);
    }
    if (Size >= sizeof(int) * 4) {
        map->def.max_entries = *(unsigned int *)(Data + sizeof(int) * 3);
    }

    // Fuzz target functions
    __u32 ifindex = bpf_map__ifindex(map);
    __u32 value_size = bpf_map__value_size(map);
    __u32 key_size = bpf_map__key_size(map);
    __u32 max_entries = bpf_map__max_entries(map);
    __u32 map_flags = bpf_map__map_flags(map);
    __u32 btf_key_type_id = bpf_map__btf_key_type_id(map);

    // Print results to avoid compiler optimizing away the calls
    printf("ifindex: %u, value_size: %u, key_size: %u, max_entries: %u, map_flags: %u, btf_key_type_id: %u\n",
           ifindex, value_size, key_size, max_entries, map_flags, btf_key_type_id);

    cleanup_dummy_bpf_map(map);
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

    LLVMFuzzerTestOneInput_20(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
