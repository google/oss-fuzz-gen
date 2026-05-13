#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include this for memcpy
#include <janet.h>

int LLVMFuzzerTestOneInput_332(const uint8_t *data, size_t size) {
    // Initialize the Janet library
    janet_init();

    // Create a JanetArray with an initial capacity
    JanetArray *array = janet_array(10);

    // Ensure that the data size is sufficient to create a Janet value
    if (size >= sizeof(Janet)) {
        // Create a Janet value from the input data
        Janet janet_value;
        memcpy(&janet_value, data, sizeof(Janet));

        // Push the Janet value into the JanetArray
        janet_array_push(array, janet_value);
    }

    // Clean up Janet resources
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

    LLVMFuzzerTestOneInput_332(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
