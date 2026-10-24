#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
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
    struct bpf_map *map = (struct bpf_map *)calloc(1, sizeof(*map));
    if (!map)
        {
        return NULL;
    }
    map->name = strdup("dummy_map");
    map->real_name = strdup("dummy_real_map");
    return map;
}

static void destroy_dummy_bpf_map(struct bpf_map *map) {
    if (map) {
        free(map->name);
        free(map->real_name);
        free(map);
    }
}

int LLVMFuzzerTestOneInput_21(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(enum bpf_map_type))
        {
        return 0;
    }

    enum bpf_map_type map_type = *(enum bpf_map_type *)Data;
    Data += sizeof(enum bpf_map_type);
    Size -= sizeof(enum bpf_map_type);

    // Fuzz libbpf_probe_bpf_map_type
    int probe_result = libbpf_probe_bpf_map_type(map_type, NULL);

    // Fuzz libbpf_bpf_map_type_str
    const char *map_type_str = libbpf_bpf_map_type_str(map_type);

    // Create a dummy bpf_map for testing
    struct bpf_map *dummy_map = create_dummy_bpf_map();
    if (!dummy_map)
        {
        return 0;
    }

    // Fuzz bpf_map__name
    const char *map_name = bpf_map__name(dummy_map);

    // Fuzz bpf_map__is_internal
    bool is_internal = bpf_map__is_internal(dummy_map);

    // Fuzz bpf_map__unpin
    int unpin_result = bpf_map__unpin(dummy_map, "./dummy_file");

    // Fuzz bpf_map__type

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bpf_map__unpin to bpf_map__reuse_fd
    long ret_libbpf_get_error_qzfsr = libbpf_get_error((const void *)"w");
    if (ret_libbpf_get_error_qzfsr < 0){
    	return 0;
    }
    // Ensure dataflow is valid (i.e., non-null)
    if (!dummy_map) {
    	return 0;
    }
    int ret_bpf_map__reuse_fd_bvmzz = bpf_map__reuse_fd(dummy_map, (int )ret_libbpf_get_error_qzfsr);
    if (ret_bpf_map__reuse_fd_bvmzz < 0){
    	return 0;
    }
    // End mutation: Producer.APPEND_MUTATOR
    

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from bpf_map__reuse_fd to bpf_map__map_extra
    // Ensure dataflow is valid (i.e., non-null)
    if (!dummy_map) {
    	return 0;
    }
    __u64 ret_bpf_map__map_extra_bjckr = bpf_map__map_extra(dummy_map);
    // End mutation: Producer.APPEND_MUTATOR
    
    enum bpf_map_type retrieved_type = bpf_map__type(dummy_map);

    // Cleanup
    destroy_dummy_bpf_map(dummy_map);

    // Use the results to prevent compiler optimizations
    (void)probe_result;
    (void)map_type_str;
    (void)map_name;
    (void)is_internal;
    (void)unpin_result;
    (void)retrieved_type;

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

    LLVMFuzzerTestOneInput_21(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
