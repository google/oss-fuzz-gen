// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open_file at libbpf.c:8445:1 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__autoattach at libbpf.c:9673:6 in libbpf.h
// bpf_program__set_autoattach at libbpf.c:9678:6 in libbpf.h
// bpf_program__autoload at libbpf.c:9659:6 in libbpf.h
// bpf_program__attach_cgroup at libbpf.c:13354:1 in libbpf.h
// bpf_program__attach_kprobe at libbpf.c:11902:18 in libbpf.h
// bpf_program__attach_lsm at libbpf.c:13302:18 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <libbpf.h>
#include <errno.h>

static struct bpf_program *initialize_bpf_program(struct bpf_object **obj) {
    *obj = bpf_object__open_file("./dummy_file", NULL);
    if (!*obj)
        return NULL;
    
    struct bpf_program *prog = bpf_object__next_program(*obj, NULL);
    if (!prog) {
        bpf_object__close(*obj);
        return NULL;
    }

    return prog;
}

static void cleanup_bpf_object(struct bpf_object *obj) {
    if (obj) {
        bpf_object__close(obj);
    }
}

static void cleanup_bpf_link(struct bpf_link *link) {
    if (link) {
        bpf_link__destroy(link);
    }
}

int LLVMFuzzerTestOneInput_105(const uint8_t *Data, size_t Size) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = initialize_bpf_program(&obj);
    if (!prog)
        return 0;

    struct bpf_link *link;
    int cgroup_fd;
    char func_name[128];

    // Fuzz bpf_program__autoattach
    bool autoattach_status = bpf_program__autoattach(prog);

    // Fuzz bpf_program__set_autoattach
    bool set_autoattach = Size > 0 ? Data[0] % 2 : 0;
    bpf_program__set_autoattach(prog, set_autoattach);

    // Fuzz bpf_program__autoload
    bool autoload_status = bpf_program__autoload(prog);

    // Fuzz bpf_program__attach_cgroup
    cgroup_fd = open("./dummy_file", O_RDONLY | O_CREAT, 0644);
    if (cgroup_fd >= 0) {
        link = bpf_program__attach_cgroup(prog, cgroup_fd);
        cleanup_bpf_link(link);
        close(cgroup_fd);
    }

    // Fuzz bpf_program__attach_kprobe
    if (Size > 1) {
        snprintf(func_name, sizeof(func_name), "func_%u", Data[1]);
        bool retprobe = Data[1] % 2;
        link = bpf_program__attach_kprobe(prog, retprobe, func_name);
        cleanup_bpf_link(link);
    }

    // Fuzz bpf_program__attach_lsm
    link = bpf_program__attach_lsm(prog);
    cleanup_bpf_link(link);

    cleanup_bpf_object(obj);
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

        LLVMFuzzerTestOneInput_105(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    