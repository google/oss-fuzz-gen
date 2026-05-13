// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_map__pin at libbpf.c:9141:5 in libbpf.h
// bpf_link__pin at libbpf.c:11322:5 in libbpf.h
// bpf_map__unpin at libbpf.c:9205:5 in libbpf.h
// bpf_object__pin_maps at libbpf.c:9279:5 in libbpf.h
// bpf_map__pin_path at libbpf.c:9259:13 in libbpf.h
// bpf_map__set_pin_path at libbpf.c:9241:5 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <libbpf.h>

// Dummy struct definitions to allow compilation
struct bpf_map {
    char *name;
    char *pin_path;
    int fd;
};

struct bpf_link {
    int fd;
    char *pin_path;
    int (*detach)(struct bpf_link *link);
    void (*dealloc)(struct bpf_link *link);
};

struct bpf_object {
    struct bpf_map *maps;
    size_t nr_maps;
};

// Initialize bpf_map
static void init_bpf_map(struct bpf_map *map) {
    map->fd = -1;
    map->name = NULL;
    map->pin_path = NULL;
}

// Initialize bpf_link
static void init_bpf_link(struct bpf_link *link) {
    link->fd = -1;
    link->pin_path = NULL;
    link->detach = NULL;
    link->dealloc = NULL;
}

// Initialize bpf_object
static void init_bpf_object(struct bpf_object *obj) {
    obj->maps = NULL;
    obj->nr_maps = 0;
}

int LLVMFuzzerTestOneInput_71(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Initialize BPF structures
    struct bpf_map map;
    struct bpf_link link;
    struct bpf_object obj;
    init_bpf_map(&map);
    init_bpf_link(&link);
    init_bpf_object(&obj);

    // Create a dummy file for pinning
    const char *dummy_file_path = "./dummy_file";
    int fd = open(dummy_file_path, O_CREAT | O_RDWR, 0600);
    if (fd < 0) return 0;
    close(fd);

    // Fuzz bpf_map__pin
    const char *path = (Size > 1 && Data[0] % 2) ? dummy_file_path : NULL;
    if (map.fd >= 0) {
        bpf_map__pin(&map, path);
    }

    // Fuzz bpf_link__pin
    path = (Size > 2 && Data[1] % 2) ? dummy_file_path : NULL;
    if (link.fd >= 0) {
        bpf_link__pin(&link, path);
    }

    // Fuzz bpf_map__unpin
    path = (Size > 3 && Data[2] % 2) ? dummy_file_path : NULL;
    if (map.fd >= 0) {
        bpf_map__unpin(&map, path);
    }

    // Fuzz bpf_object__pin_maps
    path = (Size > 4 && Data[3] % 2) ? dummy_file_path : NULL;
    if (obj.maps) {
        bpf_object__pin_maps(&obj, path);
    }

    // Fuzz bpf_map__pin_path
    const char *pin_path = bpf_map__pin_path(&map);

    // Fuzz bpf_map__set_pin_path
    path = (Size > 5 && Data[4] % 2) ? dummy_file_path : NULL;
    if (map.fd >= 0) {
        bpf_map__set_pin_path(&map, path);
    }

    // Cleanup
    unlink(dummy_file_path);

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

        LLVMFuzzerTestOneInput_71(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    