#include <stdint.h>
#include <stdlib.h>
#include <string.h>  // Include for memcpy
#include <janet.h>

int LLVMFuzzerTestOneInput_68(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an int32_t value
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Initialize Janet
    janet_init();

    // Create a JanetBuffer
    JanetBuffer *buffer = janet_buffer(10);

    // Extract an int32_t value from the input data
    int32_t count;
    memcpy(&count, data, sizeof(int32_t));

    // Set the buffer count using the extracted value
    janet_buffer_setcount(buffer, count);

    // Use remaining data to fill the buffer if possible
    if (size > sizeof(int32_t)) {
        size_t remaining_size = size - sizeof(int32_t);
        const uint8_t *remaining_data = data + sizeof(int32_t);

        // Ensure the buffer has enough space
        if (remaining_size > 0) {
            janet_buffer_push_bytes(buffer, remaining_data, remaining_size);
        }
    }

    // Optionally, perform additional operations on the buffer to increase coverage
    // For example, manipulate the buffer or call other functions that use the buffer
    // JanetArray *array = janet_array(0);
    // janet_array_push(array, janet_wrap_buffer(buffer));

    // Clean up
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

    LLVMFuzzerTestOneInput_68(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
