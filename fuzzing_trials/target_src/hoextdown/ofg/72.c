#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "/src/hoextdown/src/buffer.h"  // Correct path for hoedown_buffer_new declaration

int LLVMFuzzerTestOneInput_72(const uint8_t *data, size_t size) {
    // Ensure the size is non-zero to avoid creating a buffer of zero size
    if (size == 0) {
        return 0;
    }

    // Call the function-under-test
    hoedown_buffer *buffer = hoedown_buffer_new(size);

    // Check if the buffer was created successfully
    if (buffer == NULL) {
        return 0;
    }

    // Perform operations on the buffer
    // For example, fill the buffer with the provided data
    hoedown_buffer_put(buffer, data, size);

    // Additional operations to increase code coverage
    // Example: Try to grow the buffer and see if it handles resizing
    hoedown_buffer_grow(buffer, size * 2);

    // Example: Clear the buffer and check if it resets correctly
    hoedown_buffer_reset(buffer);

    // Additional operations to further exercise the code
    // Example: Refill the buffer after reset to ensure it can still accept data
    hoedown_buffer_put(buffer, data, size);

    // Example: Shrink the buffer to test edge cases
    hoedown_buffer_grow(buffer, size / 2);

    // Example: Reset the buffer again to ensure consistency in repeated operations
    hoedown_buffer_reset(buffer);

    // Clean up the buffer
    hoedown_buffer_free(buffer);

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

    if(size < 1 + 1)
        exit(0);

    data = (uint8_t *)malloc((size_t)size);
    if(data == NULL)
        exit(0);

    if(fread(data, (size_t)size, 1, f) != 1)
        exit(0);

    LLVMFuzzerTestOneInput_72(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
