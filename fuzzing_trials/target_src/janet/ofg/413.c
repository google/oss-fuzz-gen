#include <janet.h>
#include <stdint.h>
#include <stddef.h>

int LLVMFuzzerTestOneInput_413(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Create a JanetBuffer
    JanetBuffer *buffer = janet_buffer(10);

    // Set up some default values for the integer parameters
    int indent = 2;
    int flags = 0;

    // Create a Janet object from the input data
    Janet janet_data;
    if (size > 0) {
        janet_data = janet_stringv((const uint8_t *)data, size);
    } else {
        janet_data = janet_wrap_nil();
    }

    // Call the function-under-test
    janet_pretty(buffer, indent, flags, janet_data);

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

    LLVMFuzzerTestOneInput_413(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
