#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"
#include <limits.h>

// Define the fuzzer entry point function
int LLVMFuzzerTestOneInput_543(const uint8_t *data, size_t size) {
    // Ensure that the input data size is at least 4 bytes to safely extract an int32_t
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Extract an int32_t value from the input data
    int32_t buffer_size = *((int32_t *)data);

    // Ensure the buffer_size is within a reasonable range to prevent issues
    if (buffer_size < 0 || buffer_size > INT_MAX / 2) {
        return 0;
    }

    // Initialize the Janet runtime (this is necessary for using Janet functions)
    janet_init();

    // Call the function-under-test
    JanetBuffer *buffer = janet_buffer(buffer_size);

    // Check if the buffer was successfully created
    if (buffer != NULL) {
        // Perform operations on the buffer if needed
        // For example, you can fill the buffer with data or perform other tests

        // Clean up the buffer
        janet_buffer_deinit(buffer);
    }

    // Deinitialize the Janet runtime
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

    LLVMFuzzerTestOneInput_543(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
