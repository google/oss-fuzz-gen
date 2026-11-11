#include <stdint.h>
#include <stddef.h>
#include "janet.h" // Assuming the Janet library provides this header

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    // Initialize JanetBuffer
    JanetBuffer buffer;
    janet_buffer_init(&buffer, 10); // Initialize with a capacity of 10

    // Ensure the input size is at least 4 bytes to read a uint32_t
    if (size >= sizeof(uint32_t)) {
        // Read a uint32_t from the input data
        uint32_t value = *((uint32_t *)data);

        // Call the function-under-test
        janet_buffer_push_u32(&buffer, value);
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

    LLVMFuzzerTestOneInput_3(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
