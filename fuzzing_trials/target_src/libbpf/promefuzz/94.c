// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_object__open_subskeleton at libbpf.c:14548:5 in libbpf.h
// bpf_object__destroy_subskeleton at libbpf.c:14608:6 in libbpf.h
// bpf_object__open_file at libbpf.c:8445:1 in libbpf.h
// bpf_object__destroy_subskeleton at libbpf.c:14608:6 in libbpf.h
// bpf_object__destroy_subskeleton at libbpf.c:14608:6 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_program__set_autoattach at libbpf.c:9678:6 in libbpf.h
// bpf_program__attach_perf_event_opts at libbpf.c:11411:18 in libbpf.h
// bpf_program__unload at libbpf.c:790:6 in libbpf.h
// bpf_object__destroy_subskeleton at libbpf.c:14608:6 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <libbpf.h>

static struct bpf_object_subskeleton *create_dummy_subskeleton() {
    struct bpf_object_subskeleton *s = malloc(sizeof(struct bpf_object_subskeleton));
    if (!s)
        return NULL;
    s->sz = sizeof(struct bpf_object_subskeleton);
    s->obj = NULL;
    s->map_cnt = 0;
    s->map_skel_sz = sizeof(struct bpf_map_skeleton);
    s->maps = NULL;
    s->prog_cnt = 0;
    s->prog_skel_sz = sizeof(struct bpf_prog_skeleton);
    s->progs = NULL;
    s->var_cnt = 0;
    s->var_skel_sz = sizeof(struct bpf_var_skeleton);
    s->vars = NULL;
    return s;
}

static struct bpf_program *create_dummy_program(struct bpf_object *obj) {
    if (!obj)
        return NULL;

    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    return prog;
}

int LLVMFuzzerTestOneInput_94(const uint8_t *Data, size_t Size) {
    struct bpf_object_subskeleton *subskeleton = create_dummy_subskeleton();
    if (!subskeleton)
        return 0;

    int ret = bpf_object__open_subskeleton(subskeleton);
    if (ret < 0) {
        bpf_object__destroy_subskeleton(subskeleton);
        return 0;
    }

    struct bpf_object *obj = bpf_object__open_file("./dummy_file", NULL);
    if (!obj) {
        bpf_object__destroy_subskeleton(subskeleton);
        return 0;
    }

    struct bpf_program *program = create_dummy_program(obj);
    if (!program) {
        bpf_object__destroy_subskeleton(subskeleton);
        bpf_object__close(obj);
        return 0;
    }

    struct bpf_program *next_prog = bpf_object__next_program(obj, NULL);
    if (next_prog) {
        bpf_program__set_autoattach(next_prog, true);
        struct bpf_link *link = bpf_program__attach_perf_event_opts(next_prog, -1, NULL);
        if (!link) {
            bpf_program__unload(next_prog);
        }
    }

    bpf_object__destroy_subskeleton(subskeleton);
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

        LLVMFuzzerTestOneInput_94(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    