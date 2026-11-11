#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "/src/hoextdown/src/buffer.h"  // Correct path for hoedown_buffer and hoedown_buffer_cstr declarations

// Remove 'extern "C"' as it is not valid in C code
int LLVMFuzzerTestOneInput_22(const uint8_t *data, size_t size) {
    // Initialize a hoedown_buffer
    hoedown_buffer *buffer = hoedown_buffer_new(size);

    // Ensure the buffer is not NULL and size is greater than 0
    if (buffer == NULL || size == 0) {
        return 0;
    }

    // Copy the input data into the hoedown_buffer
    hoedown_buffer_put(buffer, data, size);

    // Call the function-under-test
    const char *result = hoedown_buffer_cstr(buffer);

    // Use the result to avoid any compiler optimizations
    if (result != NULL) {
        // Do something with result, e.g., print or log, but for fuzzing, we generally don't need to do anything
    }

    // Free the buffer
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

    LLVMFuzzerTestOneInput_22(data + 1, (size_t)(size - 1));

    free(data);
    fclose(f);
    return 0;
}
#endif
