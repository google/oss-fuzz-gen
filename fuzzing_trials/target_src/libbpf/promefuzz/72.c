// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_program__attach_perf_event at libbpf.c:11489:18 in libbpf.h
// bpf_link__detach at libbpf.c:11317:5 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_netkit at libbpf.c:13441:1 in libbpf.h
// bpf_link__detach at libbpf.c:11317:5 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_cgroup at libbpf.c:13354:1 in libbpf.h
// bpf_link__detach at libbpf.c:11317:5 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_netns at libbpf.c:13360:1 in libbpf.h
// bpf_link__detach at libbpf.c:11317:5 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_xdp at libbpf.c:13371:18 in libbpf.h
// bpf_link__detach at libbpf.c:11317:5 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_object__open at libbpf.c:8453:20 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <libbpf.h>

static struct bpf_program *create_dummy_bpf_program(struct bpf_object **obj_out) {
    // Create a dummy bpf_object using libbpf API
    struct bpf_object *obj = bpf_object__open("./dummy_file");
    if (!obj) return NULL;

    struct bpf_program *prog = bpf_object__next_program(NULL, obj);
    if (!prog) {
        bpf_object__close(obj);
        return NULL;
    }

    *obj_out = obj;
    return prog;
}

static void cleanup_bpf_program(struct bpf_object *obj) {
    if (obj) {
        bpf_object__close(obj);
    }
}

int LLVMFuzzerTestOneInput_72(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) return 0;

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = create_dummy_bpf_program(&obj);
    if (!prog) return 0;

    int fd = *((int *)Data);
    struct bpf_link *link = NULL;
    int result;

    // Fuzz bpf_program__attach_perf_event
    link = bpf_program__attach_perf_event(prog, fd);
    if (link) {
        result = bpf_link__detach(link);
        bpf_link__destroy(link);
    }

    // Fuzz bpf_program__attach_netkit
    struct bpf_netkit_opts opts = { .sz = sizeof(opts) };
    link = bpf_program__attach_netkit(prog, fd, &opts);
    if (link) {
        result = bpf_link__detach(link);
        bpf_link__destroy(link);
    }

    // Fuzz bpf_program__attach_cgroup
    link = bpf_program__attach_cgroup(prog, fd);
    if (link) {
        result = bpf_link__detach(link);
        bpf_link__destroy(link);
    }

    // Fuzz bpf_program__attach_netns
    link = bpf_program__attach_netns(prog, fd);
    if (link) {
        result = bpf_link__detach(link);
        bpf_link__destroy(link);
    }

    // Fuzz bpf_program__attach_xdp
    link = bpf_program__attach_xdp(prog, fd);
    if (link) {
        result = bpf_link__detach(link);
        bpf_link__destroy(link);
    }

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

        LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    