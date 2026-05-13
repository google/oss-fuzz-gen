// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open_file at libbpf.c:8445:1 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_program__name at libbpf.c:9649:13 in libbpf.h
// bpf_program__set_type at libbpf.c:9739:5 in libbpf.h
// bpf_object__load at libbpf.c:9040:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_program__set_autoattach at libbpf.c:9678:6 in libbpf.h
// bpf_program__autoattach at libbpf.c:9673:6 in libbpf.h
// bpf_program__autoload at libbpf.c:9659:6 in libbpf.h
// bpf_program__attach_cgroup at libbpf.c:13354:1 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_kprobe at libbpf.c:11902:18 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach_lsm at libbpf.c:13302:18 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static struct bpf_program *init_bpf_program(struct bpf_object **obj_out) {
    struct bpf_object *obj;
    struct bpf_program *prog;

    obj = bpf_object__open_file("./dummy_file", NULL);
    if (!obj)
        return NULL;

    bpf_object__for_each_program(prog, obj) {
        if (strcmp(bpf_program__name(prog), "dummy_prog") == 0) {
            bpf_program__set_type(prog, BPF_PROG_TYPE_KPROBE);
            if (bpf_object__load(obj) == 0) {
                *obj_out = obj;
                return prog;
            }
        }
    }
    bpf_object__close(obj);
    return NULL;
}

static void cleanup_bpf_program(struct bpf_object *obj) {
    if (!obj) return;
    bpf_object__close(obj);
}

int LLVMFuzzerTestOneInput_109(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    struct bpf_object *obj = NULL;
    struct bpf_program *prog = init_bpf_program(&obj);
    if (!prog) return 0;

    bool autoattach = Data[0] % 2;
    bpf_program__set_autoattach(prog, autoattach);

    bool is_autoattached = bpf_program__autoattach(prog);
    bool is_autoload = bpf_program__autoload(prog);

    int cgroup_fd = open("/dev/null", O_RDONLY);
    if (cgroup_fd >= 0) {
        struct bpf_link *link_cgroup = bpf_program__attach_cgroup(prog, cgroup_fd);
        if (link_cgroup) {
            bpf_link__destroy(link_cgroup);
        }
        close(cgroup_fd);
    }

    const char *func_name = "dummy_function";
    struct bpf_link *link_kprobe = bpf_program__attach_kprobe(prog, autoattach, func_name);
    if (link_kprobe) {
        bpf_link__destroy(link_kprobe);
    }

    struct bpf_link *link_lsm = bpf_program__attach_lsm(prog);
    if (link_lsm) {
        bpf_link__destroy(link_lsm);
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

        LLVMFuzzerTestOneInput_109(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    