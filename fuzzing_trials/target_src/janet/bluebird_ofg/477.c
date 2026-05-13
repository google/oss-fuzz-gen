#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdlib.h>
#include "janet.h"

int LLVMFuzzerTestOneInput_477(const uint8_t *data, size_t size) {
    JanetArray *array;
    Janet wrapped_array;
    Janet *elements;
    size_t num_elements, i;

    // Ensure that the size is a multiple of sizeof(Janet)
    if (size % sizeof(Janet) != 0) {
        return 0;
    }

    num_elements = size / sizeof(Janet);

    // Initialize the Janet library
    janet_init();

    // Allocate memory for the array and its elements
    array = janet_array(num_elements);
    elements = array->data;

    // Initialize elements from the input data
    for (i = 0; i < num_elements; i++) {
        elements[i] = ((Janet *)data)[i];
    }

    // Set the length of the array
    array->count = num_elements;

    // Call the function-under-test
    wrapped_array = janet_wrap_array(array);

    // Cleanup: decrement the reference count of the array
    janet_gcroot(wrapped_array);
    janet_gcunroot(wrapped_array);

    // Deinitialize the Janet library
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

    LLVMFuzzerTestOneInput_477(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
