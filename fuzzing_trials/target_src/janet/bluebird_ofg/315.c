#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

// Ensure the Janet library is initialized
static void initialize_janet_315() {
    static int initialized = 0;
    if (!initialized) {
        janet_init();
        initialized = 1;
    }
}

int LLVMFuzzerTestOneInput_315(const uint8_t *data, size_t size) {
    // Initialize Janet if not already initialized
    initialize_janet_315();

    // Ensure that the size is at least the size of a Janet array
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Calculate the number of elements we can safely allocate
    size_t num_elements = size / sizeof(int32_t);

    // Attempt to create a Janet array from the data
    JanetArray *array = janet_array(num_elements);
    for (size_t i = 0; i < num_elements && i < array->capacity; i++) {
        array->data[i] = janet_wrap_integer(((int32_t *)data)[i]);
    }
    array->count = num_elements;

    // Create a Janet struct from the array
    Janet *values = janet_tuple_begin(num_elements);
    for (size_t i = 0; i < num_elements; i++) {
        values[i] = array->data[i];
    }
    JanetTuple tuple = janet_tuple_end(values);

    // Call the function-under-test
    for (size_t i = 0; i < num_elements; i++) {
        Janet result = janet_get(janet_wrap_tuple(tuple), janet_wrap_integer(i));
        if (janet_checktype(result, JANET_NIL)) {
            // Perform some operation if needed
        }
    }

    // Clean up
    // No need to explicitly destroy the array, as Janet's garbage collector will handle it.
    // However, if we had manually rooted the array, we would unroot it here.

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

    LLVMFuzzerTestOneInput_315(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
