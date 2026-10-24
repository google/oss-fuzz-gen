// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open_file at libbpf.c:8445:1 in libbpf.h
// libbpf_get_error at libbpf.c:11207:6 in libbpf_legacy.h
// bpf_object__load at libbpf.c:9040:5 in libbpf.h
// bpf_object__find_program_by_name at libbpf.c:4521:1 in libbpf.h
// bpf_tc_query at netlink.c:881:5 in libbpf.h
// bpf_tc_detach at netlink.c:869:5 in libbpf.h
// bpf_tc_hook_create at netlink.c:631:5 in libbpf.h
// bpf_program__attach_tcx at libbpf.c:13406:1 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_tc_attach at netlink.c:734:5 in libbpf.h
// bpf_tc_hook_destroy at netlink.c:647:5 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>

static void initialize_bpf_tc_hook(struct bpf_tc_hook *hook, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct bpf_tc_hook)) return;
    hook->sz = sizeof(struct bpf_tc_hook);
    hook->ifindex = *(int *)Data;
    hook->attach_point = BPF_TC_INGRESS;
    hook->parent = *(uint32_t *)(Data + 4);
    hook->handle = *(uint32_t *)(Data + 8);
    hook->qdisc = "fq_codel";
}

static void initialize_bpf_tc_opts(struct bpf_tc_opts *opts, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct bpf_tc_opts)) return;
    opts->sz = sizeof(struct bpf_tc_opts);
    opts->prog_fd = *(int *)Data;
    opts->flags = *(uint32_t *)(Data + 4);
    opts->prog_id = *(uint32_t *)(Data + 8);
    opts->handle = *(uint32_t *)(Data + 12);
    opts->priority = *(uint32_t *)(Data + 16);
}

static struct bpf_program *load_bpf_program(struct bpf_object **obj) {
    // Mocked program loading
    struct bpf_program *prog = NULL;
    struct bpf_object_open_opts open_opts = {
        .relaxed_maps = true,
    };

    *obj = bpf_object__open_file("dummy_program.o", &open_opts);
    if (!libbpf_get_error(*obj)) {
        bpf_object__load(*obj);
        prog = bpf_object__find_program_by_name(*obj, "dummy_program");
    }

    return prog;
}

int LLVMFuzzerTestOneInput_63(const uint8_t *Data, size_t Size) {
    struct bpf_tc_hook hook;
    struct bpf_tc_opts opts;
    struct bpf_program *prog;
    struct bpf_object *obj = NULL;
    struct bpf_link *link;
    int ifindex = 1; // Mock interface index

    if (Size < sizeof(struct bpf_tc_hook) + sizeof(struct bpf_tc_opts)) return 0;

    initialize_bpf_tc_hook(&hook, Data, Size);
    initialize_bpf_tc_opts(&opts, Data, Size);

    // Fuzz bpf_tc_query
    bpf_tc_query(&hook, &opts);

    // Fuzz bpf_tc_detach
    bpf_tc_detach(&hook, &opts);

    // Fuzz bpf_tc_hook_create
    bpf_tc_hook_create(&hook);

    // Load a mocked BPF program
    prog = load_bpf_program(&obj);
    if (prog) {
        // Fuzz bpf_program__attach_tcx
        link = bpf_program__attach_tcx(prog, ifindex, NULL);
        if (link) {
            bpf_link__destroy(link);
        }
        bpf_object__close(obj);
    }

    // Fuzz bpf_tc_attach
    bpf_tc_attach(&hook, &opts);

    // Fuzz bpf_tc_hook_destroy
    bpf_tc_hook_destroy(&hook);

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

        LLVMFuzzerTestOneInput_63(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    