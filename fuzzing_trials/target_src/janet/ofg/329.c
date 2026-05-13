#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h> // Include string.h for memcpy
#include "janet.h" // Assuming janet.h is the header file where JanetBuffer is defined

int LLVMFuzzerTestOneInput_329(const uint8_t *data, size_t size) {
    // Initialize JanetBuffer
    JanetBuffer buffer;
    buffer.data = (uint8_t *)malloc(size);
    buffer.count = 0;
    buffer.capacity = size;

    // Ensure the buffer is not NULL
    if (buffer.data == NULL) {
        return 0;
    }

    // Populate the buffer with input data
    memcpy(buffer.data, data, size);
    buffer.count = size; // Set the count to the size of the input data

    // Define the length and growth parameters
    int32_t length = (int32_t)(size % 1000); // Ensure length is within a reasonable range
    int32_t growth = (int32_t)(size % 100);  // Ensure growth is within a reasonable range

    // Call the function-under-test
    janet_buffer_ensure(&buffer, length, growth);

    // Additional operations to increase code coverage
    if (buffer.capacity > 0) {
        // Simulate some operations on the buffer to ensure it's being used
        for (int32_t i = 0; i < buffer.count; i++) {
            buffer.data[i] ^= 0xFF; // Example operation: bitwise NOT
        }
    }

    // Clean up
    free(buffer.data);

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

    LLVMFuzzerTestOneInput_329(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
