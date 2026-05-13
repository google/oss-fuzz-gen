#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_491(const uint8_t *data, size_t size) {
    // Initialize the Janet runtime
    janet_init();

    // Ensure the size is large enough to create a Janet array
    if (size < sizeof(Janet)) {
        janet_deinit();
        return 0;
    }

    // Create a Janet array
    JanetArray *array = janet_array(size);

    // Copy the input data into the Janet array
    for (size_t i = 0; i < size; i++) {
        janet_array_push(array, janet_wrap_integer(data[i]));
    }

    // Use a fixed index for demonstration purposes
    int32_t index = 0;

    // Ensure the index is within bounds
    if (index >= 0 && index < array->count) {
        // Call the function-under-test
        Janet value = array->data[index];

        // Additional code can be added here to further manipulate or examine value
    }

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

    LLVMFuzzerTestOneInput_491(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
