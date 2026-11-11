// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__open at libbpf.c:8453:20 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_program__attach_kprobe_opts at libbpf.c:11806:1 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__pin at libbpf.c:9093:5 in libbpf.h
// bpf_program__unpin at libbpf.c:9120:5 in libbpf.h
// bpf_program__attach_uprobe_multi at libbpf.c:12628:1 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__fd at libbpf.c:9714:5 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>

static void cleanup_bpf_object(struct bpf_object *obj) {
    if (obj) {
        bpf_object__close(obj);
    }
}

int LLVMFuzzerTestOneInput_79(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(struct bpf_kprobe_opts) + 1)
        return 0;

    struct bpf_object *obj = bpf_object__open("dummy_prog.o");
    if (!obj)
        return 0;

    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    if (!prog) {
        cleanup_bpf_object(obj);
        return 0;
    }

    struct bpf_kprobe_opts opts;
    memcpy(&opts, Data, sizeof(opts));
    opts.sz = sizeof(opts);

    const char *dummy_func_name = "dummy_func";
    struct bpf_link *link = bpf_program__attach_kprobe_opts(prog, dummy_func_name, &opts);
    if (link) {
        bpf_link__destroy(link);
    }

    const char *pin_path = "./dummy_file";
    int fd = open(pin_path, O_RDWR | O_CREAT, 0644);
    if (fd >= 0) {
        close(fd);
        bpf_program__pin(prog, pin_path);
        bpf_program__unpin(prog, pin_path);
        unlink(pin_path);
    }

    struct bpf_uprobe_multi_opts uprobe_opts;
    memcpy(&uprobe_opts, Data, sizeof(uprobe_opts));
    uprobe_opts.sz = sizeof(uprobe_opts);

    link = bpf_program__attach_uprobe_multi(prog, 0, "/bin/ls", "main", &uprobe_opts);
    if (link) {
        bpf_link__destroy(link);
    }

    int fd_result = bpf_program__fd(prog);

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

        LLVMFuzzerTestOneInput_79(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    