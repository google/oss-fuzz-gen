#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"
#include <string.h>

// Function signature for the fuzzer
int LLVMFuzzerTestOneInput_549(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Ensure there's enough data for a Janet object and an int32_t index
    if (size < sizeof(int32_t) + 1) { // Ensure there's at least 1 byte for string
        janet_deinit();
        return 0;
    }

    // Create a Janet array from the input data
    JanetArray *array = janet_array(1);
    array->data[0] = janet_wrap_string(janet_string(data, size - sizeof(int32_t)));

    // Extract an int32_t index from the remaining input data
    int32_t index = *(const int32_t *)(data + size - sizeof(int32_t));

    // Ensure the index is within bounds
    if (array->count > 0) { // Check to prevent division by zero
        index = index % array->count;
        if (index < 0) {
            index += array->count;
        }

        // Call the function under test
        JanetKeyword result = janet_getkeyword(array->data, index);

        // Use the result in some way to prevent optimizations from removing the call
        (void)result;
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

    LLVMFuzzerTestOneInput_549(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
