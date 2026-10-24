// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// perf_buffer__new at libbpf.c:13920:21 in libbpf.h
// perf_buffer__free at libbpf.c:13844:6 in libbpf.h
// perf_buffer__epoll_fd at libbpf.c:14183:5 in libbpf.h
// perf_buffer__poll at libbpf.c:14188:5 in libbpf.h
// perf_buffer__buffer at libbpf.c:14235:5 in libbpf.h
// perf_buffer__consume_buffer at libbpf.c:14259:5 in libbpf.h
// perf_buffer__consume at libbpf.c:14273:5 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <libbpf.h>

static void dummy_sample_cb(void *ctx, int cpu, void *data, __u32 size) {
}

static void dummy_lost_cb(void *ctx, int cpu, __u64 cnt) {
}

static struct perf_buffer *create_dummy_perf_buffer() {
    struct perf_buffer_opts pb_opts = {};
    struct perf_buffer *pb = perf_buffer__new(-1, 1, dummy_sample_cb, dummy_lost_cb, NULL, &pb_opts);

    return pb;
}

static void destroy_dummy_perf_buffer(struct perf_buffer *pb) {
    if (pb) {
        perf_buffer__free(pb);
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int)) {
        return 0;
    }

    struct perf_buffer *pb = create_dummy_perf_buffer();
    if (!pb) {
        return 0;
    }

    // Fuzz perf_buffer__epoll_fd
    int epoll_fd = perf_buffer__epoll_fd(pb);
    if (epoll_fd < 0) {
        goto cleanup;
    }

    // Fuzz perf_buffer__poll
    int timeout_ms = *(int *)Data;
    int poll_result = perf_buffer__poll(pb, timeout_ms);

    // Fuzz perf_buffer__buffer
    void *buf = NULL;
    size_t buf_size = 0;
    int buffer_result = perf_buffer__buffer(pb, 0, &buf, &buf_size);

    // Fuzz perf_buffer__consume_buffer
    size_t buf_idx = 0;
    int consume_buffer_result = perf_buffer__consume_buffer(pb, buf_idx);

    // Fuzz perf_buffer__consume
    int consume_result = perf_buffer__consume(pb);

cleanup:
    destroy_dummy_perf_buffer(pb);
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

        LLVMFuzzerTestOneInput_5(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    