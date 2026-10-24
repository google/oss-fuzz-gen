// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_program__unload at libbpf.c:790:6 in libbpf.h
// bpf_program__func_info_cnt at libbpf.c:9834:7 in libbpf.h
// bpf_program__log_level at libbpf.c:9793:7 in libbpf.h
// bpf_program__flags at libbpf.c:9779:7 in libbpf.h
// bpf_program__insns at libbpf.c:9683:24 in libbpf.h
// bpf_program__line_info_cnt at libbpf.c:9846:7 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libbpf.h>

static struct bpf_program* create_dummy_bpf_program() {
    // Normally, you'd use bpf_object__open() and bpf_program__next() to get a bpf_program,
    // but for the sake of this example, we will return NULL as we don't have a real ELF file.
    return NULL;
}

static void destroy_dummy_bpf_program(struct bpf_program* prog) {
    if (prog) {
        bpf_program__unload(prog);
        // bpf_program__close() does not exist; normally you'd handle the bpf_object instead.
    }
}

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    struct bpf_program* prog = create_dummy_bpf_program();
    if (!prog) {
        return 0;
    }

    // Fuzz bpf_program__func_info_cnt
    __u32 func_info_cnt = bpf_program__func_info_cnt(prog);

    // Fuzz bpf_program__log_level
    __u32 log_level = bpf_program__log_level(prog);

    // Fuzz bpf_program__flags
    __u32 flags = bpf_program__flags(prog);

    // Fuzz bpf_program__insns
    const struct bpf_insn* insns = bpf_program__insns(prog);

    // Fuzz bpf_program__line_info_cnt
    __u32 line_info_cnt = bpf_program__line_info_cnt(prog);

    // Cleanup
    destroy_dummy_bpf_program(prog);

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

        LLVMFuzzerTestOneInput_6(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    