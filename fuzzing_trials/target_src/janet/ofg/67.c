#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h" // Assume this is the correct header for JanetBuffer

int LLVMFuzzerTestOneInput_67(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to extract an int32_t value
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Initialize a JanetBuffer
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10); // Initialize with a non-zero capacity

    // Extract an int32_t value from the data
    int32_t count = *(const int32_t *)data;

    // Ensure count is within a reasonable range to avoid excessive memory usage
    if (count < 0) {
        count = -count; // Make count positive
    }
    count = count % 1000; // Limit count to a maximum of 1000

    // Call the function-under-test
    janet_buffer_setcount(&buffer, count);

    // Optionally, perform some operations on the buffer to increase code coverage
    if (buffer.count > 0) {
        memset(buffer.data, 0, buffer.count); // Fill buffer with zeros
    }

    // Clean up the buffer
    janet_buffer_deinit(&buffer);

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

    LLVMFuzzerTestOneInput_67(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
