// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open_file at libbpf.c:8445:1 in libbpf.h
// bpf_object__pin at libbpf.c:9417:5 in libbpf.h
// bpf_object__unpin at libbpf.c:9434:5 in libbpf.h
// bpf_object__pin_maps at libbpf.c:9279:5 in libbpf.h
// bpf_object__find_map_fd_by_name at libbpf.c:11079:1 in libbpf.h
// bpf_object__gen_loader at libbpf.c:9577:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static void init_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "dummy content");
        fclose(file);
    }
}

static struct bpf_object *open_bpf_object() {
    init_dummy_file();
    struct bpf_object *obj = bpf_object__open_file("./dummy_file", NULL);
    return obj;
}

int LLVMFuzzerTestOneInput_55(const uint8_t *Data, size_t Size) {
    if (Size == 0) return 0;

    char path[256];
    snprintf(path, sizeof(path), "/sys/fs/bpf/%.*s", (int)Size, Data);

    struct bpf_object *obj = open_bpf_object();
    if (!obj) return 0;

    // Test bpf_object__pin
    bpf_object__pin(obj, path);

    // Test bpf_object__unpin
    bpf_object__unpin(obj, path);

    // Test bpf_object__pin_maps
    bpf_object__pin_maps(obj, path);

    // Test bpf_object__find_map_fd_by_name
    char map_name[256];
    snprintf(map_name, sizeof(map_name), "%.*s", (int)Size, Data);
    bpf_object__find_map_fd_by_name(obj, map_name);

    // Test bpf_object__gen_loader
    struct gen_loader_opts opts = {0};
    bpf_object__gen_loader(obj, &opts);

    bpf_object__close(obj);

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

        LLVMFuzzerTestOneInput_55(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    