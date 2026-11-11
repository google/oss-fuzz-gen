#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_463(const uint8_t *data, size_t size) {
    // Initialize Janet VM
    janet_init();

    // Ensure data is not empty
    if (size > 0) {
        // Use the input data to create a Janet string
        Janet value = janet_wrap_string(janet_string(data, size));

        // Create a JanetArray and push the value
        JanetArray *array = janet_array(1);
        janet_array_push(array, value);

        // Optionally, invoke more Janet functions to increase coverage
        // For example, convert the array to a tuple and back
        JanetTuple tuple = janet_tuple_n(array->data, array->count);
        JanetArray *new_array = janet_array(0);
        for (int i = 0; i < janet_tuple_length(tuple); i++) {
            janet_array_push(new_array, tuple[i]);
        }
    }

    // Clean up Janet VM
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

    LLVMFuzzerTestOneInput_463(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
