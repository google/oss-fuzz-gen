// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__load at libbpf.c:9040:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_object__prev_program at libbpf.c:9633:1 in libbpf.h
// bpf_object__find_program_by_name at libbpf.c:4521:1 in libbpf.h
// bpf_program__log_buf at libbpf.c:9807:13 in libbpf.h
// bpf_program__name at libbpf.c:9649:13 in libbpf.h
// bpf_program__unload at libbpf.c:790:6 in libbpf.h
// bpf_program__line_info_cnt at libbpf.c:9846:7 in libbpf.h
// bpf_object__open at libbpf.c:8453:20 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>

static struct bpf_object *create_dummy_bpf_object() {
    struct bpf_object *obj = bpf_object__open("./dummy_file");
    if (!obj) return NULL;

    // Load the object to ensure programs are initialized
    if (bpf_object__load(obj) != 0) {
        bpf_object__close(obj);
        return NULL;
    }

    return obj;
}

static void cleanup_dummy_bpf_object(struct bpf_object *obj) {
    if (!obj) return;
    bpf_object__close(obj);
}

int LLVMFuzzerTestOneInput_107(const uint8_t *Data, size_t Size) {
    struct bpf_object *obj = create_dummy_bpf_object();
    if (!obj) return 0;

    struct bpf_program *prog = NULL;
    struct bpf_program *iter_prog = NULL;

    // Iterate through programs to find a suitable one
    bpf_object__for_each_program(iter_prog, obj) {
        if (Size > 0 && Data[0] % 2 == 0) {
            prog = iter_prog;
            break;
        }
    }

    // Test bpf_object__prev_program
    struct bpf_program *prev_prog = bpf_object__prev_program(obj, prog);
    (void)prev_prog;

    // Test bpf_object__find_program_by_name
    char name[64] = {0};
    if (Size > 1) {
        size_t name_len = (Size - 1) < 63 ? (Size - 1) : 63;
        memcpy(name, &Data[1], name_len);
        struct bpf_program *found_prog = bpf_object__find_program_by_name(obj, name);
        (void)found_prog;
    }

    // Test bpf_program__log_buf
    if (prog) {
        size_t log_size = 0;
        const char *log_buf = bpf_program__log_buf(prog, &log_size);
        (void)log_buf;
    }

    // Test bpf_program__name
    if (prog) {
        const char *prog_name = bpf_program__name(prog);
        (void)prog_name;
    }

    // Test bpf_program__unload
    if (prog) {
        bpf_program__unload(prog);
    }

    // Test bpf_program__line_info_cnt
    if (prog) {
        __u32 line_info_cnt = bpf_program__line_info_cnt(prog);
        (void)line_info_cnt;
    }

    cleanup_dummy_bpf_object(obj);
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

        LLVMFuzzerTestOneInput_107(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    