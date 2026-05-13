#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "janet.h" // Assume this is the correct header file for JanetBuffer

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    if (size < 1) {
        return 0; // Not enough data to proceed
    }

    // Initialize a JanetBuffer
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10); // Initialize with a capacity of 10

    // Use the data to fill the buffer to test more thoroughly
    for (size_t i = 0; i < size; i++) {
        janet_buffer_push_u8(&buffer, data[i]);
    }

    // Optionally, you can add more operations on the buffer to increase coverage
    // For example, manipulate buffer contents, query its state, etc.

    // Clean up
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

    LLVMFuzzerTestOneInput_18(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
