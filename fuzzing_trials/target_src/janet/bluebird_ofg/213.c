#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_213(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Ensure the size is sufficient to create a Janet array
    if (size < sizeof(Janet)) {
        janet_deinit();
        return 0;
    }

    // Create a Janet array
    JanetArray *array = janet_array(0);

    // Populate the Janet array with the input data
    for (size_t i = 0; i < size / sizeof(Janet); i++) {
        Janet value = janet_wrap_integer(data[i]);
        janet_array_push(array, value);
    }

    // Fuzz the janet_getindexed function
    if (array->count > 0) {
        // Create a Janet array and wrap it
        Janet wrapped_array = janet_wrap_array(array);
        Janet *argv = &wrapped_array;

        // Get the indexed value
        JanetView result = janet_getindexed(argv, 0);

        // Use the result to avoid compiler optimizations
        if (result.items != NULL) {
            // Do something with result.items if needed
        }
    }

    // Clean up the Janet environment
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

    LLVMFuzzerTestOneInput_213(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
