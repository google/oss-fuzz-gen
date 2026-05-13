// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open_file at libbpf.c:8445:1 in libbpf.h
// bpf_object__load at libbpf.c:9040:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_tc_query at netlink.c:881:5 in libbpf.h
// bpf_tc_attach at netlink.c:734:5 in libbpf.h
// bpf_tc_detach at netlink.c:869:5 in libbpf.h
// bpf_tc_hook_create at netlink.c:631:5 in libbpf.h
// bpf_tc_hook_destroy at netlink.c:647:5 in libbpf.h
// bpf_program__attach_tcx at libbpf.c:13406:1 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__unload at libbpf.c:790:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <libbpf.h>

static void initialize_bpf_tc_hook(struct bpf_tc_hook *hook, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct bpf_tc_hook)) return;
    memcpy(hook, Data, sizeof(struct bpf_tc_hook));
    hook->sz = sizeof(struct bpf_tc_hook);
}

static void initialize_bpf_tc_opts(struct bpf_tc_opts *opts, const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct bpf_tc_opts)) return;
    memcpy(opts, Data, sizeof(struct bpf_tc_opts));
    opts->sz = sizeof(struct bpf_tc_opts);
}

static struct bpf_program* load_bpf_program(const char *file) {
    struct bpf_object *obj;
    struct bpf_program *prog;
    
    obj = bpf_object__open_file(file, NULL);
    if (!obj)
        return NULL;
    if (bpf_object__load(obj)) {
        bpf_object__close(obj);
        return NULL;
    }
    prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        bpf_object__close(obj);
        return NULL;
    }
    return prog;
}

int LLVMFuzzerTestOneInput_66(const uint8_t *Data, size_t Size) {
    struct bpf_tc_hook hook = {0};
    struct bpf_tc_opts opts = {0};
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int ifindex = 1; // Example interface index

    // Initialize structures with fuzz data
    initialize_bpf_tc_hook(&hook, Data, Size);
    initialize_bpf_tc_opts(&opts, Data, Size);

    // Create a dummy BPF program
    prog = load_bpf_program("./dummy_file");
    if (!prog)
        return 0;

    // Fuzz bpf_tc_query
    bpf_tc_query(&hook, &opts);

    // Fuzz bpf_tc_attach
    bpf_tc_attach(&hook, &opts);

    // Fuzz bpf_tc_detach
    bpf_tc_detach(&hook, &opts);

    // Fuzz bpf_tc_hook_create
    bpf_tc_hook_create(&hook);

    // Fuzz bpf_tc_hook_destroy
    bpf_tc_hook_destroy(&hook);

    // Fuzz bpf_program__attach_tcx
    link = bpf_program__attach_tcx(prog, ifindex, NULL);
    if (link) {
        bpf_link__destroy(link);
    }

    // Cleanup
    bpf_program__unload(prog);
    
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

        LLVMFuzzerTestOneInput_66(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    