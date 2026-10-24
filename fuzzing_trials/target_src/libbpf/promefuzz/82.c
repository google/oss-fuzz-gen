// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open at libbpf.c:8453:20 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_program__expected_attach_type at libbpf.c:9764:22 in libbpf.h
// libbpf_bpf_attach_type_str at libbpf.c:10289:13 in libbpf.h
// libbpf_prog_type_by_name at libbpf.c:10263:5 in libbpf.h
// libbpf_bpf_prog_type_str at libbpf.c:10313:13 in libbpf.h
// libbpf_probe_bpf_prog_type at libbpf_probes.c:205:5 in libbpf.h
// bpf_program__type at libbpf.c:9728:20 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>

static struct bpf_program *create_dummy_bpf_program(struct bpf_object **obj_out) {
    struct bpf_object *obj = bpf_object__open("./dummy_file");
    if (!obj) return NULL;

    struct bpf_program *prog = bpf_object__next_program(NULL, obj);
    if (!prog) {
        bpf_object__close(obj);
        return NULL;
    }

    *obj_out = obj;
    return prog;
}

static void cleanup_dummy_bpf_program(struct bpf_object *obj) {
    if (obj) {
        bpf_object__close(obj);
    }
}

int LLVMFuzzerTestOneInput_82(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    struct bpf_object *dummy_obj = NULL;
    struct bpf_program *dummy_prog = create_dummy_bpf_program(&dummy_obj);
    if (!dummy_prog) return 0;

    // Test bpf_program__expected_attach_type
    enum bpf_attach_type attach_type = bpf_program__expected_attach_type(dummy_prog);
    const char *attach_type_str = libbpf_bpf_attach_type_str(attach_type);

    // Test libbpf_prog_type_by_name
    char name[Size + 1];
    memcpy(name, Data, Size);
    name[Size] = '\0';
    enum bpf_prog_type prog_type;
    enum bpf_attach_type expected_attach_type;
    int res = libbpf_prog_type_by_name(name, &prog_type, &expected_attach_type);

    // Test libbpf_bpf_prog_type_str
    const char *prog_type_str = libbpf_bpf_prog_type_str(prog_type);

    // Test libbpf_probe_bpf_prog_type
    int probe_res = libbpf_probe_bpf_prog_type(prog_type, NULL);

    // Test bpf_program__type
    enum bpf_prog_type prog_type_from_prog = bpf_program__type(dummy_prog);

    cleanup_dummy_bpf_program(dummy_obj);
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

        LLVMFuzzerTestOneInput_82(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    