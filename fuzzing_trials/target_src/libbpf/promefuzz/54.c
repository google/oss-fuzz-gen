// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open_file at libbpf.c:8445:1 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__unpin at libbpf.c:9434:5 in libbpf.h
// bpf_object__pin_programs at libbpf.c:9357:5 in libbpf.h
// bpf_object__unpin_programs at libbpf.c:9394:5 in libbpf.h
// bpf_object__pin_maps at libbpf.c:9279:5 in libbpf.h
// bpf_object__unpin_maps at libbpf.c:9327:5 in libbpf.h
// bpf_object__pin at libbpf.c:9417:5 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>

static struct bpf_object *create_dummy_bpf_object(void) {
    // Allocating memory for the bpf_object using libbpf's API
    struct bpf_object *obj = bpf_object__open_file("/dev/null", NULL);
    if (!obj) return NULL;
    return obj;
}

static void cleanup_bpf_object(struct bpf_object *obj) {
    if (obj) bpf_object__close(obj);
}

int LLVMFuzzerTestOneInput_54(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least one byte for the path

    char path[256];
    snprintf(path, sizeof(path), "./dummy_file_%zu", Size);

    struct bpf_object *obj = create_dummy_bpf_object();
    if (!obj) return 0;

    // Fuzz bpf_object__unpin
    bpf_object__unpin(obj, path);

    // Fuzz bpf_object__pin_programs
    bpf_object__pin_programs(obj, path);

    // Fuzz bpf_object__unpin_programs
    bpf_object__unpin_programs(obj, path);

    // Fuzz bpf_object__pin_maps
    bpf_object__pin_maps(obj, path);

    // Fuzz bpf_object__unpin_maps
    bpf_object__unpin_maps(obj, path);

    // Fuzz bpf_object__pin
    bpf_object__pin(obj, path);

    cleanup_bpf_object(obj);
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

        LLVMFuzzerTestOneInput_54(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    