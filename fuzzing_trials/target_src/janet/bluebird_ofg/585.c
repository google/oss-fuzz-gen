#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_585(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a JanetBuffer
    JanetBuffer *buffer = janet_buffer(10);

    // Ensure the size is sufficient to create a valid Janet object
    if (size < sizeof(Janet)) {
        // Clean up Janet runtime
        janet_deinit();
        return 0;
    }

    // Create a Janet object from the data
    Janet janet_obj = janet_wrap_string(janet_string(data, size));

    // Call the function-under-test
    janet_to_string_b(buffer, janet_obj);

    // Clean up Janet runtime
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

    LLVMFuzzerTestOneInput_585(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
