// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_object__open at libbpf.c:8453:20 in libbpf.h
// bpf_object__next_program at libbpf.c:9621:1 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_object__open at libbpf.c:8453:20 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
// bpf_program__attach_kprobe_opts at libbpf.c:11806:1 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__section_name at libbpf.c:9654:13 in libbpf.h
// bpf_object__find_program_by_name at libbpf.c:4521:1 in libbpf.h
// bpf_program__name at libbpf.c:9649:13 in libbpf.h
// bpf_program__attach_sockmap at libbpf.c:13366:1 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__attach at libbpf.c:13596:18 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_object__close at libbpf.c:9478:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static struct bpf_program *create_dummy_bpf_program() {
    // Create a dummy bpf_program using libbpf's API
    struct bpf_object *obj = bpf_object__open("./dummy_file");
    if (!obj) {
        return NULL;
    }
    struct bpf_program *prog = bpf_object__next_program(obj, NULL);
    bpf_object__close(obj); // Close the object as we only need the program
    return prog;
}

static struct bpf_object *create_dummy_bpf_object() {
    // Create a dummy bpf_object using libbpf's API
    struct bpf_object *obj = bpf_object__open("./dummy_file");
    return obj;
}

int LLVMFuzzerTestOneInput_51(const uint8_t *Data, size_t Size) {
    struct bpf_program *prog = create_dummy_bpf_program();
    struct bpf_object *obj = create_dummy_bpf_object();
    if (!prog || !obj) {
        bpf_object__close(obj);
        return 0;
    }

    // Fuzz bpf_program__attach_kprobe_opts
    struct bpf_kprobe_opts opts = {0};
    opts.sz = sizeof(opts);
    if (Size >= sizeof(uint64_t) + sizeof(size_t) + 1) {
        opts.bpf_cookie = *(uint64_t *)Data;
        opts.offset = *(size_t *)(Data + sizeof(uint64_t));
        opts.retprobe = Data[sizeof(uint64_t) + sizeof(size_t)] % 2;
        opts.attach_mode = PROBE_ATTACH_MODE_DEFAULT;

        struct bpf_link *link = bpf_program__attach_kprobe_opts(prog, NULL, &opts);
        if (link) {
            bpf_link__destroy(link);
        }
    }

    // Fuzz bpf_program__section_name
    const char *sec_name = bpf_program__section_name(prog);

    // Fuzz bpf_object__find_program_by_name
    const char *name = (const char *)Data;
    struct bpf_program *found_prog = bpf_object__find_program_by_name(obj, name);

    // Fuzz bpf_program__name
    const char *prog_name = bpf_program__name(prog);

    // Fuzz bpf_program__attach_sockmap
    int dummy_fd = open("./dummy_file", O_CREAT | O_RDWR, 0644);
    if (dummy_fd != -1) {
        struct bpf_link *sockmap_link = bpf_program__attach_sockmap(prog, dummy_fd);
        if (sockmap_link) {
            bpf_link__destroy(sockmap_link);
        }
        close(dummy_fd);
    }

    // Fuzz bpf_program__attach
    struct bpf_link *attach_link = bpf_program__attach(prog);
    if (attach_link) {
        bpf_link__destroy(attach_link);
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

        LLVMFuzzerTestOneInput_51(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    