// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open_skeleton at libbpf.c:14518:5 in libbpf.h
// bpf_object__load_skeleton at libbpf.c:14618:5 in libbpf.h
// bpf_object__set_kversion at libbpf.c:9567:5 in libbpf.h
// bpf_object__prepare at libbpf.c:9035:5 in libbpf.h
// bpf_object__load at libbpf.c:9040:5 in libbpf.h
// bpf_object__destroy_skeleton at libbpf.c:14751:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <libbpf.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_35(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct bpf_object_skeleton)) {
        return 0;
    }

    struct bpf_object_skeleton skeleton;
    memset(&skeleton, 0, sizeof(skeleton));

    struct bpf_object_open_opts opts;
    memset(&opts, 0, sizeof(opts));

    struct bpf_object *bpf_obj = NULL;

    // Fuzz bpf_object__open_skeleton
    int ret = bpf_object__open_skeleton(&skeleton, &opts);
    if (ret == 0) {
        // Fuzz bpf_object__load_skeleton
        ret = bpf_object__load_skeleton(&skeleton);
    }

    // If the skeleton is successfully opened, attempt to load it
    if (ret == 0) {
        bpf_obj = *skeleton.obj;
        // Fuzz bpf_object__set_kversion
        bpf_object__set_kversion(bpf_obj, 0);

        // Fuzz bpf_object__prepare
        ret = bpf_object__prepare(bpf_obj);
        if (ret == 0) {
            // Fuzz bpf_object__load
            bpf_object__load(bpf_obj);
        }
    }

    // Cleanup
    if (skeleton.obj && *skeleton.obj) {
        bpf_object__destroy_skeleton(&skeleton);
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

        LLVMFuzzerTestOneInput_35(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    