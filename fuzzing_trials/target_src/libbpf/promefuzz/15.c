// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_program__attach at libbpf.c:13596:18 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_trace_opts at libbpf.c:13296:18 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_iter at libbpf.c:13512:1 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_raw_tracepoint at libbpf.c:13208:18 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_trace at libbpf.c:13291:18 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_lsm at libbpf.c:13302:18 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_object__open at libbpf.c:8453:20 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <libbpf.h>

static struct bpf_program *create_dummy_bpf_program(struct bpf_object **obj) {
    *obj = bpf_object__open("./dummy_file");
    if (!*obj) return NULL;

    struct bpf_program *prog = bpf_object__next_program(*obj, NULL);
    if (!prog) {
        bpf_object__close(*obj);
        return NULL;
    }

    return prog;
}

static struct bpf_trace_opts *create_dummy_trace_opts() {
    struct bpf_trace_opts *opts = (struct bpf_trace_opts *)malloc(sizeof(struct bpf_trace_opts));
    if (!opts) return NULL;

    opts->sz = sizeof(struct bpf_trace_opts);
    opts->cookie = 0xdeadbeef;
    return opts;
}

static struct bpf_iter_attach_opts *create_dummy_iter_attach_opts() {
    struct bpf_iter_attach_opts *opts = (struct bpf_iter_attach_opts *)malloc(sizeof(struct bpf_iter_attach_opts));
    if (!opts) return NULL;

    opts->sz = sizeof(struct bpf_iter_attach_opts);
    opts->link_info = NULL;
    opts->link_info_len = 0;
    return opts;
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = create_dummy_bpf_program(&obj);
    if (!prog) return 0;

    struct bpf_trace_opts *trace_opts = create_dummy_trace_opts();
    struct bpf_iter_attach_opts *iter_opts = create_dummy_iter_attach_opts();

    // Fuzz bpf_program__attach
    struct bpf_link *link = bpf_program__attach(prog);
    if (link) {
        bpf_link__destroy(link);
    }

    // Fuzz bpf_program__attach_trace_opts
    link = bpf_program__attach_trace_opts(prog, trace_opts);
    if (link) {
        bpf_link__destroy(link);
    }

    // Fuzz bpf_program__attach_iter
    link = bpf_program__attach_iter(prog, iter_opts);
    if (link) {
        bpf_link__destroy(link);
    }

    // Fuzz bpf_program__attach_raw_tracepoint
    link = bpf_program__attach_raw_tracepoint(prog, "dummy_tp");
    if (link) {
        bpf_link__destroy(link);
    }

    // Fuzz bpf_program__attach_trace
    link = bpf_program__attach_trace(prog);
    if (link) {
        bpf_link__destroy(link);
    }

    // Fuzz bpf_program__attach_lsm
    link = bpf_program__attach_lsm(prog);
    if (link) {
        bpf_link__destroy(link);
    }

    free(trace_opts);
    free(iter_opts);

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

        LLVMFuzzerTestOneInput_15(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    