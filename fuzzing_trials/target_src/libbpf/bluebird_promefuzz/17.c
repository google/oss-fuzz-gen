#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "libbpf.h"

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_17(const uint8_t *Data, size_t Size) {
    struct bpf_object_skeleton *skeleton = NULL;
    struct bpf_object_open_opts opts = {0};
    struct bpf_object *obj = NULL;
    int ret;

    // Use the input data to initialize opts
    if (Size > 0) {
        opts.object_name = (const char *)Data;
    }

    // Prepare dummy file if needed
    write_dummy_file(Data, Size);

    // Allocate memory for skeleton
    skeleton = (struct bpf_object_skeleton *)calloc(1, sizeof(struct bpf_object_skeleton));
    if (!skeleton) {
        return 0;
    }

    // Fuzz bpf_object__open_skeleton
    ret = bpf_object__open_skeleton(skeleton, &opts);
    if (ret < 0) {
        goto cleanup;
    }

    // Fuzz bpf_object__prepare
    ret = bpf_object__prepare(obj);
    if (ret < 0) {
        goto cleanup;
    }

    // Fuzz bpf_object__load
    ret = bpf_object__load(obj);
    if (ret < 0) {
        goto cleanup;
    }

    // Fuzz bpf_object__load_skeleton
    ret = bpf_object__load_skeleton(skeleton);
    if (ret < 0) {
        goto cleanup;
    }

    // Fuzz bpf_object__pin
    ret = bpf_object__pin(obj, "./dummy_file");
    if (ret < 0) {
        goto cleanup;
    }

cleanup:
    // Fuzz bpf_object__destroy_skeleton
    if (skeleton) {
        bpf_object__destroy_skeleton(skeleton);
        // Remove the manual free to avoid double-free
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

    LLVMFuzzerTestOneInput_17(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
