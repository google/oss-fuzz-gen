#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>  // Include for malloc
#include "janet.h"   // Include for Janet functions

int LLVMFuzzerTestOneInput_570(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Ensure that the size is large enough to create at least one Janet element
    if (size < sizeof(int32_t)) {
        janet_deinit();
        return 0;
    }

    // Calculate the number of Janet elements we can create from the input data
    int32_t num_elements = size / sizeof(int32_t);

    // Allocate memory for Janet elements
    Janet *janet_elements = (Janet *)malloc(num_elements * sizeof(Janet));
    if (!janet_elements) {
        janet_deinit();
        return 0;
    }

    // Copy data into Janet elements
    for (int32_t i = 0; i < num_elements; i++) {
        janet_elements[i] = janet_wrap_integer(((int32_t *)data)[i]);
    }

    // Call the function-under-test
    JanetArray *array = janet_array(num_elements);
    if (!array) {
        free(janet_elements);
        janet_deinit();
        return 0;
    }

    for (int32_t i = 0; i < num_elements; i++) {
        janet_array_push(array, janet_elements[i]);
    }

    // Optionally: perform operations on the returned array
    // (e.g., access elements, modify, etc.)

    // Cleanup
    free(janet_elements);

    // Deinitialize the Janet environment
    janet_deinit();

    // Return 0 to indicate successful execution
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

    LLVMFuzzerTestOneInput_570(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
