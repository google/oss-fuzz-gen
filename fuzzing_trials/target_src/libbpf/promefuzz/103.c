// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__find_program_by_name at libbpf.c:4521:1 in libbpf.h
// bpf_program__unload at libbpf.c:790:6 in libbpf.h
// bpf_object__open at libbpf.c:8453:20 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_program__insn_cnt at libbpf.c:9688:8 in libbpf.h
// bpf_program__set_insns at libbpf.c:9693:5 in libbpf.h
// bpf_program__insns at libbpf.c:9683:24 in libbpf.h
// bpf_program__fd at libbpf.c:9714:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>
#include <fcntl.h>
#include <unistd.h>

#define DUMMY_INSN_COUNT 10
#define FUZZ_INSN_COUNT 5

static struct bpf_program *initialize_bpf_program(struct bpf_object *obj) {
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, "dummy_prog");
    if (!prog) return NULL;

    struct bpf_insn *insns = (struct bpf_insn *)malloc(sizeof(struct bpf_insn) * DUMMY_INSN_COUNT);
    if (!insns) {
        return NULL;
    }

    return prog;
}

static void cleanup_bpf_program(struct bpf_program *prog) {
    if (prog) {
        bpf_program__unload(prog);
    }
}

int LLVMFuzzerTestOneInput_103(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct bpf_insn) * FUZZ_INSN_COUNT) return 0;

    // Create a dummy file and object
    FILE *file = fopen("./dummy_file", "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    struct bpf_object *obj = bpf_object__open("./dummy_file");
    if (!obj) return 0;

    struct bpf_program *prog = initialize_bpf_program(obj);
    if (!prog) {
        bpf_object__close(obj);
        return 0;
    }

    // Fuzz bpf_program__insn_cnt
    size_t insn_cnt = bpf_program__insn_cnt(prog);

    // Fuzz bpf_program__set_insns
    struct bpf_insn *new_insns = (struct bpf_insn *)malloc(sizeof(struct bpf_insn) * FUZZ_INSN_COUNT);
    if (new_insns) {
        memcpy(new_insns, Data, sizeof(struct bpf_insn) * FUZZ_INSN_COUNT);
        int set_insns_result = bpf_program__set_insns(prog, new_insns, FUZZ_INSN_COUNT);
        free(new_insns);
    }

    // Fuzz bpf_program__insns
    const struct bpf_insn *insns = bpf_program__insns(prog);

    // Fuzz bpf_program__fd
    int fd = bpf_program__fd(prog);

    cleanup_bpf_program(prog);
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

        LLVMFuzzerTestOneInput_103(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    