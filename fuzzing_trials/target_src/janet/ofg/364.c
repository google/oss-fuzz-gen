#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_364(const uint8_t *data, size_t size) {
    int32_t input_size;

    // Ensure there is enough data to read an int32_t
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Copy the first 4 bytes of data to input_size
    input_size = *(int32_t *)data;

    // Ensure input_size is positive and within a reasonable limit to avoid negative or excessively large buffer size
    if (input_size <= 0 || input_size > 1024 * 1024) { // Limiting the buffer size to 1MB for safety
        return 0;
    }

    // Call the function-under-test
    JanetBuffer *buffer = janet_buffer(input_size);

    // Check if buffer is successfully created
    if (buffer == NULL) {
        return 0;
    }

    // Use the buffer for some operations if necessary
    // Ensure we don't read beyond the provided data
    size_t bytes_to_copy = size - sizeof(int32_t);
    if (bytes_to_copy > 0) {
        janet_buffer_push_bytes(buffer, data + sizeof(int32_t), bytes_to_copy);
    }

    // Clean up the buffer
    janet_buffer_deinit(buffer);

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

    LLVMFuzzerTestOneInput_364(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
