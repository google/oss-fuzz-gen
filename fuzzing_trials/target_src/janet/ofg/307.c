#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h" // Assuming this header defines JanetBuffer

int LLVMFuzzerTestOneInput_307(const uint8_t *data, size_t size) {
    // Initialize a JanetBuffer
    JanetBuffer buffer;
    buffer.data = (uint8_t *)malloc(size);
    buffer.capacity = size;
    buffer.count = size;

    // Copy the input data to the buffer
    if (buffer.data != NULL) {
        for (size_t i = 0; i < size; i++) {
            buffer.data[i] = data[i];
        }
    }

    // Define an int32_t value for extra space
    int32_t extra_space = 10; // Arbitrary non-zero value

    // Call the function-under-test
    janet_buffer_extra(&buffer, extra_space);

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

    LLVMFuzzerTestOneInput_307(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
