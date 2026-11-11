#include <stddef.h>
#include <stdint.h>
#include <linux/perf_event.h>
#include "/src/libbpf/src/libbpf.h"

struct perf_buffer *perf_buffer__new_raw(int, size_t, struct perf_event_attr *, perf_buffer_event_fn, void *, const struct perf_buffer_raw_opts *);

// Remove the 'extern "C"' as it is not needed in a C file
int LLVMFuzzerTestOneInput_109(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int fd = 1; // File descriptor, assuming a valid non-zero fd
    size_t page_cnt = 8; // Arbitrary non-zero page count
    struct perf_event_attr attr = {}; // Initialize perf_event_attr structure
    perf_buffer_event_fn event_cb = NULL; // Event callback function, set to NULL
    void *ctx = (void *)data; // Context, using the input data
    struct perf_buffer_raw_opts opts = {}; // Initialize perf_buffer_raw_opts structure

    // Call the function-under-test
    struct perf_buffer *pb = perf_buffer__new_raw(fd, page_cnt, &attr, event_cb, ctx, &opts);

    // Normally, you would do something with the perf_buffer here
    // For fuzzing purposes, we just need to call the function

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
