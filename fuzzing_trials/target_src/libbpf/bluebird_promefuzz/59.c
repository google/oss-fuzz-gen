#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "libbpf.h"
#include <errno.h>
#include <stdbool.h>

static struct bpf_program *create_dummy_bpf_program(struct bpf_object *obj) {
    if (!obj) return NULL;
    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    return prog;
}

static void cleanup_bpf_program(struct bpf_object *obj) {
    if (obj) {
        bpf_object__close(obj);
    }
}

static void cleanup_bpf_link(struct bpf_link *link) {
    if (link) {
        bpf_link__destroy(link);
    }
}

int LLVMFuzzerTestOneInput_59(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Create a dummy BPF object
    struct bpf_object *obj = bpf_object__open("./dummy_file");
    if (!obj) return 0;

    struct bpf_program *prog = create_dummy_bpf_program(obj);
    if (!prog) {
        cleanup_bpf_program(obj);
        return 0;
    }

    // Fuzzing bpf_program__attach_uprobe
    bool retprobe = Data[0] % 2;
    pid_t pid = Data[0];
    char binary_path[] = "./dummy_file";
    size_t func_offset = 0;
    FILE *file = fopen(binary_path, "w");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
    struct bpf_link *link = bpf_program__attach_uprobe(prog, retprobe, pid, binary_path, func_offset);
    cleanup_bpf_link(link);

    // Fuzzing bpf_program__attach_tracepoint
    const char *tp_category = "dummy_category";
    const char *tp_name = "dummy_name";
    link = bpf_program__attach_tracepoint(prog, tp_category, tp_name);
    cleanup_bpf_link(link);

    // Fuzzing bpf_program__attach
    link = bpf_program__attach(prog);
    cleanup_bpf_link(link);

    // Fuzzing bpf_program__attach_raw_tracepoint
    const char *raw_tp_name = "dummy_raw_tp";
    link = bpf_program__attach_raw_tracepoint(prog, raw_tp_name);
    cleanup_bpf_link(link);

    // Fuzzing bpf_program__attach_kprobe
    const char *func_name = "dummy_func";
    link = bpf_program__attach_kprobe(prog, retprobe, func_name);
    cleanup_bpf_link(link);

    // Fuzzing bpf_program__attach_kprobe_multi_opts
    struct bpf_kprobe_multi_opts opts = {0};
    opts.sz = sizeof(opts);
    opts.cnt = 1;
    opts.syms = (const char **)&func_name;
    link = bpf_program__attach_kprobe_multi_opts(prog, func_name, &opts);
    cleanup_bpf_link(link);

    cleanup_bpf_program(obj);
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

    LLVMFuzzerTestOneInput_59(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
