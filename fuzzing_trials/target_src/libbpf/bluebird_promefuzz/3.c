#include <sys/stat.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include "libbpf.h"

// Dummy implementation of bpf_program since it's forward-declared
struct bpf_program {
    int fd;
};

static int get_random_int(const uint8_t **data, size_t *size) {
    if (*size < sizeof(int)) {
        return 0;
    }
    int value = *((int *)(*data));
    *data += sizeof(int);
    *size -= sizeof(int);
    return value;
}

static __u32 get_random_u32(const uint8_t **data, size_t *size) {
    if (*size < sizeof(__u32)) {
        return 0;
    }
    __u32 value = *((__u32 *)(*data));
    *data += sizeof(__u32);
    *size -= sizeof(__u32);
    return value;
}

static struct bpf_program *get_dummy_bpf_program() {
    static struct bpf_program dummy_prog;
    memset(&dummy_prog, 0, sizeof(dummy_prog));
    dummy_prog.fd = -1; // Initialize with an invalid FD for testing
    return &dummy_prog;
}

int LLVMFuzzerTestOneInput_3(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    int ifindex = get_random_int(&Data, &Size);
    int flags = get_random_int(&Data, &Size);

    // Fuzz bpf_xdp_query
    struct bpf_xdp_query_opts query_opts = { .sz = sizeof(query_opts) };
    bpf_xdp_query(ifindex, flags, &query_opts);

    // Fuzz bpf_xdp_query_id
    __u32 prog_id = 0;
    bpf_xdp_query_id(ifindex, flags, &prog_id);

    // Fuzz bpf_xdp_attach
    struct bpf_xdp_attach_opts attach_opts = { .sz = sizeof(attach_opts) };
    int prog_fd = get_random_int(&Data, &Size);
    bpf_xdp_attach(ifindex, prog_fd, flags, &attach_opts);

    // Fuzz bpf_program__attach_tcx
    struct bpf_tcx_opts tcx_opts = { .sz = sizeof(tcx_opts) };
    struct bpf_program *prog = get_dummy_bpf_program();
    if (prog->fd >= 0) { // Ensure valid fd before calling
        bpf_program__attach_tcx(prog, ifindex, &tcx_opts);
    }

    // Fuzz bpf_xdp_detach
    bpf_xdp_detach(ifindex, flags, &attach_opts);

    // Fuzz bpf_program__attach_xdp
    if (prog->fd >= 0) { // Ensure valid fd before calling
        bpf_program__attach_xdp(prog, ifindex);
    }

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

    LLVMFuzzerTestOneInput_3(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
