#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "/src/libbpf/src/libbpf.h"
#include "/src/libbpf/src/bpf.h" // Include additional header for perf_buffer-related functions

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    struct perf_buffer *pb;
    struct perf_buffer_opts pb_opts = {};
    int timeout;

    // Use the first few bytes of data to set the timeout value
    if (size >= sizeof(int)) {
        timeout = *((int *)data);
    } else {
        timeout = 100; // Default timeout if not enough data
    }

    // Initialize the perf_buffer using libbpf's API
    pb = perf_buffer__new(-1, 1, NULL, &pb_opts, NULL, NULL);
    if (!pb) {
        return 0; // Exit if perf_buffer creation fails
    }

    // Call the function-under-test
    int result = perf_buffer__poll(pb, timeout);

    // Clean up
    perf_buffer__free(pb);

    return result;
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

    LLVMFuzzerTestOneInput_116(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
