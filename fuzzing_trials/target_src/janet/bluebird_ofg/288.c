#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_288(const uint8_t *data, size_t size) {
    // Initialize Janet
    janet_init();

    // Create a new JanetBuffer
    JanetBuffer *buffer = janet_buffer(10);

    // Ensure the size is at least the size of uint64_t
    if (size < sizeof(uint64_t)) {
        janet_deinit();
        return 0;
    }

    // Extract a uint64_t value from the input data
    uint64_t value;
    memcpy(&value, data, sizeof(uint64_t));

    // Call the function-under-test
    janet_buffer_push_u64(buffer, value);

    // Clean up Janet
    janet_deinit();

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

    if(size < 2 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_288(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
