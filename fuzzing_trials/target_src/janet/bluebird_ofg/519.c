#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_519(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Initialize a JanetBuffer
    JanetBuffer *buffer = janet_buffer(size);

    // Ensure the buffer is not NULL and has a size
    if (buffer == NULL || size == 0) {
        janet_deinit();
        return 0;
    }

    // Fill the buffer with the provided data
    janet_buffer_push_bytes(buffer, data, size);

    // Call the function-under-test
    Janet result = janet_wrap_buffer(buffer);

    // Clean up by decrementing the buffer's reference count
    janet_buffer_deinit(buffer);

    // Deinitialize the Janet environment
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

    LLVMFuzzerTestOneInput_519(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
