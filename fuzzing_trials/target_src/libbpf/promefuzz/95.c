// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open_mem at libbpf.c:8459:1 in libbpf.h
// bpf_object__kversion at libbpf.c:9547:14 in libbpf.h
// bpf_object__load at libbpf.c:9040:5 in libbpf.h
// bpf_object__btf at libbpf.c:9557:13 in libbpf.h
// bpf_object__name at libbpf.c:9542:13 in libbpf.h
// bpf_object__btf_fd at libbpf.c:9562:5 in libbpf.h
// bpf_object__token_fd at libbpf.c:9552:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <libbpf.h>

static struct bpf_object *create_dummy_bpf_object() {
    struct bpf_object_open_opts opts = {
        .sz = sizeof(struct bpf_object_open_opts),
    };

    struct bpf_object *obj = bpf_object__open_mem(NULL, 0, &opts);
    if (!obj) return NULL;

    return obj;
}

int LLVMFuzzerTestOneInput_95(const uint8_t *Data, size_t Size) {
    struct bpf_object *obj = create_dummy_bpf_object();
    if (!obj) return 0;

    // Fuzz bpf_object__kversion
    unsigned int kversion = bpf_object__kversion(obj);
    if (kversion == 0) {
        fprintf(stderr, "bpf_object__kversion returned 0\n");
    }

    // Fuzz bpf_object__load
    int load_result = bpf_object__load(obj);
    if (load_result < 0) {
        fprintf(stderr, "bpf_object__load failed: %s\n", strerror(errno));
    }

    // Fuzz bpf_object__btf
    struct btf *btf = bpf_object__btf(obj);
    if (!btf) {
        fprintf(stderr, "bpf_object__btf returned NULL\n");
    }

    // Fuzz bpf_object__name
    const char *name = bpf_object__name(obj);
    if (!name) {
        fprintf(stderr, "bpf_object__name returned NULL\n");
    }

    // Fuzz bpf_object__btf_fd
    int btf_fd = bpf_object__btf_fd(obj);
    if (btf_fd == -1) {
        fprintf(stderr, "bpf_object__btf_fd returned -1\n");
    }

    // Fuzz bpf_object__token_fd
    int token_fd = bpf_object__token_fd(obj);
    if (token_fd == -1) {
        fprintf(stderr, "bpf_object__token_fd returned -1\n");
    }

    // Cleanup
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

        LLVMFuzzerTestOneInput_95(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    