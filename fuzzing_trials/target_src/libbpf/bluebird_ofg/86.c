#include <sys/stat.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "/src/libbpf/include/uapi/linux/perf_event.h"
#include "libbpf.h"

int LLVMFuzzerTestOneInput_86(const uint8_t *data, size_t size) {
    if (size < sizeof(struct perf_event_attr) + sizeof(struct perf_buffer_raw_opts)) {
        return 0;
    }

    int fd = 1;  // Example file descriptor, should be a valid perf event FD in real scenarios
    size_t page_cnt = 8;  // Example page count

    // Initialize perf_event_attr from the input data
    struct perf_event_attr *attr = (struct perf_event_attr *)data;

    // Initialize perf_buffer_raw_opts from the input data
    const struct perf_buffer_raw_opts *opts = (const struct perf_buffer_raw_opts *)(data + sizeof(struct perf_event_attr));

    // Example callback function
    void *ctx = NULL;
    perf_buffer_event_fn cb = NULL;

    // Call the function-under-test
    struct perf_buffer *pb = perf_buffer__new_raw(fd, page_cnt, attr, cb, ctx, opts);

    // Clean up
    if (pb) {
        perf_buffer__free(pb);
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

    LLVMFuzzerTestOneInput_86(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
