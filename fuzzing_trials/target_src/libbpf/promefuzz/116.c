// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open_file at libbpf.c:8445:1 in libbpf.h
// bpf_object__load at libbpf.c:9040:5 in libbpf.h
// bpf_object__next_map at libbpf.c:11031:1 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_program__attach at libbpf.c:13596:18 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_link__update_map at libbpf.c:13700:5 in libbpf.h
// bpf_map__set_autoattach at libbpf.c:5011:5 in libbpf.h
// bpf_map__is_internal at libbpf.c:10949:6 in libbpf.h
// bpf_map__set_autocreate at libbpf.c:5002:5 in libbpf.h
// bpf_object__find_map_fd_by_name at libbpf.c:11079:1 in libbpf.h
// bpf_map__fd at libbpf.c:10689:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <libbpf.h>

static struct bpf_object *create_dummy_bpf_object() {
    // Create a dummy BPF object
    struct bpf_object_open_opts opts = {};
    struct bpf_object *obj = bpf_object__open_file("./dummy_file", &opts);
    if (obj) {
        bpf_object__load(obj);
    }
    return obj;
}

static struct bpf_map *create_dummy_bpf_map(struct bpf_object *obj) {
    // Find a map in the object
    if (!obj) {
        return NULL;
    }
    return bpf_object__next_map(obj, NULL);
}

static struct bpf_link *create_dummy_bpf_link(struct bpf_object *obj) {
    // Create a dummy BPF link using the first program in the object
    if (!obj) {
        return NULL;
    }
    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        return NULL;
    }
    return bpf_program__attach(prog);
}

int LLVMFuzzerTestOneInput_116(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    struct bpf_object *obj = create_dummy_bpf_object();
    struct bpf_map *map = create_dummy_bpf_map(obj);
    struct bpf_link *link = create_dummy_bpf_link(obj);

    if (!obj || !map || !link) {
        bpf_object__close(obj);
        bpf_link__destroy(link);
        return 0;
    }

    // Fuzz bpf_link__update_map
    bpf_link__update_map(link, map);

    // Fuzz bpf_map__set_autoattach
    bool autoattach = Data[0] % 2;
    bpf_map__set_autoattach(map, autoattach);

    // Fuzz bpf_map__is_internal
    bpf_map__is_internal(map);

    // Fuzz bpf_map__set_autocreate
    bool autocreate = Data[0] % 2;
    bpf_map__set_autocreate(map, autocreate);

    // Fuzz bpf_object__find_map_fd_by_name
    char name[16];
    snprintf(name, sizeof(name), "map_%zu", Size);
    bpf_object__find_map_fd_by_name(obj, name);

    // Fuzz bpf_map__fd
    bpf_map__fd(map);

    bpf_object__close(obj);
    bpf_link__destroy(link);

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

        LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    