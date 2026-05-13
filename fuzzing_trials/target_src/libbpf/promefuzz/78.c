// This fuzz driver is generated for library libbpf, aiming to fuzz the following functions:
// perf_buffer__new_raw at libbpf.c:13953:21 in libbpf.h
// perf_buffer__new at libbpf.c:13920:21 in libbpf.h
// perf_buffer__free at libbpf.c:13844:6 in libbpf.h
// perf_buffer__buffer_cnt at libbpf.c:14211:8 in libbpf.h
// perf_buffer__buffer_fd at libbpf.c:14221:5 in libbpf.h
// perf_buffer__buffer at libbpf.c:14235:5 in libbpf.h
// perf_buffer__consume_buffer at libbpf.c:14259:5 in libbpf.h
// perf_buffer__free at libbpf.c:13844:6 in libbpf.h
// perf_buffer__free at libbpf.c:13844:6 in libbpf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <linux/perf_event.h>
#include <libbpf.h>

static enum bpf_perf_event_ret dummy_event_cb(void *ctx, int cpu, struct perf_event_header *event) {
    return LIBBPF_PERF_EVENT_CONT;
}

static void dummy_sample_cb(void *ctx, int cpu, void *data, __u32 size) {
}

static void dummy_lost_cb(void *ctx, int cpu, __u64 lost_cnt) {
}

int LLVMFuzzerTestOneInput_78(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) + sizeof(size_t)) {
        return 0;
    }

    int map_fd = *(int *)Data;
    size_t page_cnt = *(size_t *)(Data + sizeof(int));

    struct perf_event_attr attr = {
        .type = PERF_TYPE_SOFTWARE,
        .size = sizeof(struct perf_event_attr),
        .config = 0,
    };

    struct perf_buffer_raw_opts raw_opts = {
        .sz = sizeof(struct perf_buffer_raw_opts),
        .cpu_cnt = 0,
        .cpus = NULL,
        .map_keys = NULL,
    };

    struct perf_buffer_opts opts = {
        .sz = sizeof(struct perf_buffer_opts),
        .sample_period = 1,
    };

    struct perf_buffer *pb_raw = perf_buffer__new_raw(map_fd, page_cnt, &attr, dummy_event_cb, NULL, &raw_opts);
    if (!pb_raw) {
        return 0;
    }

    struct perf_buffer *pb = perf_buffer__new(map_fd, page_cnt, dummy_sample_cb, dummy_lost_cb, NULL, &opts);
    if (!pb) {
        perf_buffer__free(pb_raw);
        return 0;
    }

    size_t cpu_cnt = perf_buffer__buffer_cnt(pb);
    for (size_t i = 0; i < cpu_cnt; ++i) {
        int fd = perf_buffer__buffer_fd(pb, i);
        if (fd < 0) {
            continue;
        }

        void *buf;
        size_t buf_size;
        if (perf_buffer__buffer(pb, i, &buf, &buf_size) == 0) {
            perf_buffer__consume_buffer(pb, i);
        }
    }

    perf_buffer__free(pb);
    perf_buffer__free(pb_raw);

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

        LLVMFuzzerTestOneInput_78(data + 1, (size_t)(size - 1));

        free(data);
        fclose(f);
        return 0;
    }
    #endif
    