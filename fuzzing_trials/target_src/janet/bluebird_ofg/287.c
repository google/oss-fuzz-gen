#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_287(const uint8_t *data, size_t size) {
    // Initialize the Janet runtime
    janet_init();

    // Create a Janet array with some elements for testing
    JanetArray *array = janet_array(10);
    for (int i = 0; i < 10; i++) {
        janet_array_push(array, janet_wrap_integer(i));
    }

    // Ensure there is enough data to extract an int32_t index
    if (size < sizeof(int32_t)) {
        janet_deinit();
        return 0;
    }

    // Extract an int32_t index from the input data
    int32_t index;
    memcpy(&index, data, sizeof(int32_t));

    // Wrap the array in a Janet object
    Janet janet_obj = janet_wrap_array(array);

    // Ensure the index is within bounds
    if (index < 0 || index >= array->count) {
        janet_deinit();
        return 0;
    }

    // Convert the index to a Janet type
    Janet janet_index = janet_wrap_integer(index);

    // Call the function-under-test
    Janet result = janet_get(janet_obj, janet_index);

    // The result is not used further, as we're only interested in testing the function call
    (void)result;

    // Clean up the Janet runtime
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

    LLVMFuzzerTestOneInput_287(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
