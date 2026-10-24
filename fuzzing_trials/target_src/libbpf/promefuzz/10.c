// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// bpf_program__attach_netns at libbpf.c:13360:1 in libbpf.h
// bpf_link__destroy at libbpf.c:11254:5 in libbpf.h
// bpf_program__set_attach_target at libbpf.c:14293:5 in libbpf.h
// libbpf_probe_bpf_prog_type at libbpf_probes.c:205:5 in libbpf.h
// bpf_program__clone at libbpf.c:9851:5 in libbpf.h
// bpf_program__set_expected_attach_type at libbpf.c:9769:5 in libbpf.h
// bpf_program__set_type at libbpf.c:9739:5 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <libbpf.h>
#include <bpf.h>

static int dummy_netns_fd() {
    int fd = open("/proc/self/ns/net", O_RDONLY);
    if (fd < 0) {
        perror("open");
    }
    return fd;
}

static struct bpf_program *dummy_bpf_program() {
    // Normally, you would load a BPF object and get a program from it.
    // For fuzzing, we'll assume this function returns a valid program pointer.
    return NULL;
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    int netns_fd = dummy_netns_fd();
    struct bpf_program *prog = dummy_bpf_program();

    if (!prog) {
        if (netns_fd >= 0) close(netns_fd);
        return 0;
    }

    // Fuzz bpf_program__attach_netns
    struct bpf_link *link = bpf_program__attach_netns(prog, netns_fd);
    if (link) {
        bpf_link__destroy(link);
    }

    // Fuzz bpf_program__set_attach_target
    int attach_prog_fd = (Size > 1) ? Data[0] : 0;
    const char *attach_func_name = (Size > 2) ? (const char *)&Data[1] : NULL;
    bpf_program__set_attach_target(prog, attach_prog_fd, attach_func_name);

    // Fuzz libbpf_probe_bpf_prog_type
    enum bpf_prog_type prog_type = (enum bpf_prog_type)(Data[0] % BPF_PROG_TYPE_SOCKET_FILTER);
    libbpf_probe_bpf_prog_type(prog_type, NULL);

    // Fuzz bpf_program__clone
    struct bpf_prog_load_opts opts = {};
    opts.sz = sizeof(struct bpf_prog_load_opts);
    bpf_program__clone(prog, &opts);

    // Fuzz bpf_program__set_expected_attach_type
    enum bpf_attach_type attach_type = (enum bpf_attach_type)(Data[0] % BPF_TRACE_RAW_TP);
    bpf_program__set_expected_attach_type(prog, attach_type);

    // Fuzz bpf_program__set_type
    bpf_program__set_type(prog, prog_type);

    // Cleanup
    if (netns_fd >= 0) close(netns_fd);
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

        LLVMFuzzerTestOneInput_10(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    