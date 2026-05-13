// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open at libbpf.c:8453:20 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_program__fd at libbpf.c:9714:5 in libbpf.h
// bpf_program__set_flags at libbpf.c:9784:5 in libbpf.h
// bpf_program__attach_cgroup_opts at libbpf.c:13378:1 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__set_autoload at libbpf.c:9664:5 in libbpf.h
// bpf_program__clone at libbpf.c:9851:5 in libbpf.h
// bpf_program__set_log_level at libbpf.c:9798:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <bpf.h>

// Dummy implementation to create a valid bpf_program
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

static struct bpf_cgroup_opts create_dummy_cgroup_opts() {
    struct bpf_cgroup_opts opts = {0};
    opts.sz = sizeof(opts);
    opts.relative_fd = -1;
    opts.relative_id = 0;
    return opts;
}

int LLVMFuzzerTestOneInput_88(const uint8_t *Data, size_t Size) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = create_dummy_bpf_program(&obj);
    if (!prog) return 0;

    // Fuzz bpf_program__fd
    int fd = bpf_program__fd(prog);
    if (fd >= 0) close(fd);

    // Fuzz bpf_program__set_flags
    if (Size >= sizeof(__u32)) {
        __u32 flags = *((__u32 *)Data);
        bpf_program__set_flags(prog, flags);
    }

    // Fuzz bpf_program__attach_cgroup_opts
    int cgroup_fd = open("./dummy_file", O_WRONLY | O_CREAT, 0644);
    if (cgroup_fd >= 0) {
        struct bpf_cgroup_opts opts = create_dummy_cgroup_opts();
        struct bpf_link *link = bpf_program__attach_cgroup_opts(prog, cgroup_fd, &opts);
        if (!link) {
            // Handle error
        } else {
            bpf_link__destroy(link);
        }
        close(cgroup_fd);
    }

    // Fuzz bpf_program__set_autoload
    if (Size >= sizeof(bool)) {
        bool autoload = *((bool *)Data);
        bpf_program__set_autoload(prog, autoload);
    }

    // Fuzz bpf_program__clone
    struct bpf_prog_load_opts load_opts;
    memset(&load_opts, 0, sizeof(load_opts));
    load_opts.sz = sizeof(load_opts);
    fd = bpf_program__clone(prog, &load_opts);
    if (fd >= 0) close(fd);

    // Fuzz bpf_program__set_log_level
    if (Size >= sizeof(__u32)) {
        __u32 log_level = *((__u32 *)Data);
        bpf_program__set_log_level(prog, log_level);
    }

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

        LLVMFuzzerTestOneInput_88(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    