#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

// Remove 'extern "C"' as it is not needed in a C file
int LLVMFuzzerTestOneInput_108(const uint8_t *data, size_t size) {
    JanetBuffer *buffer;
    Janet janet_value;

    // Initialize the Janet runtime
    janet_init();

    // Allocate and initialize a JanetBuffer
    buffer = janet_buffer(size);
    if (buffer == NULL) {
        return 0;
    }

    // Initialize a Janet value from the input data
    if (size > 0) {
        janet_value = janet_wrap_string(janet_string(data, size));
    } else {
        janet_value = janet_wrap_nil();
    }

    // Call the function-under-test
    janet_description_b(buffer, janet_value);

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

    LLVMFuzzerTestOneInput_108(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
