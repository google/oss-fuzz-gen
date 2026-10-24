#include <sys/stat.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "libbpf.h"

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

static struct bpf_map *init_bpf_map(const uint8_t *Data, size_t Size) {
    struct bpf_map *map = (struct bpf_map *)calloc(1, sizeof(struct bpf_map));
    if (!map) return NULL;

    if (Size > 0) map->map_ifindex = Data[0];
    if (Size > 1) map->def.max_entries = Data[1];
    if (Size > 2) map->def.map_flags = Data[2];
    if (Size > 3) map->numa_node = Data[3];
    if (Size > 4) map->btf_value_type_id = Data[4];
    if (Size > 5) map->btf_key_type_id = Data[5];

    return map;
}

static void cleanup_bpf_map(struct bpf_map *map) {
    if (map) {
        free(map);
    }
}

int LLVMFuzzerTestOneInput_48(const uint8_t *Data, size_t Size) {
    struct bpf_map *map = init_bpf_map(Data, Size);
    if (!map) return 0;

    __u32 ifindex = bpf_map__ifindex(map);
    __u32 max_entries = bpf_map__max_entries(map);
    __u32 map_flags = bpf_map__map_flags(map);
    __u32 numa_node = bpf_map__numa_node(map);
    __u32 btf_value_type_id = bpf_map__btf_value_type_id(map);
    __u32 btf_key_type_id = bpf_map__btf_key_type_id(map);

    (void)ifindex;
    (void)max_entries;
    (void)map_flags;
    (void)numa_node;
    (void)btf_value_type_id;
    (void)btf_key_type_id;

    cleanup_bpf_map(map);
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

    LLVMFuzzerTestOneInput_48(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
