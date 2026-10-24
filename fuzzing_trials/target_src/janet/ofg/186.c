#include <stdint.h>
#include "/src/janet/src/include/janet.h"

// Fuzzing function
int LLVMFuzzerTestOneInput_186(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Create a Janet array from the input data
    JanetArray *array = janet_array(size);

    // Fill the array with data from the fuzz input
    for (size_t i = 0; i < size; i++) {
        janet_array_push(array, janet_wrap_integer(data[i]));
    }

    // Perform some operations on the array to simulate usage
    // For example, get the length of the array
    Janet length = janet_wrap_integer(array->count);

    // Call the function-under-test
    janet_sweep();

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

    LLVMFuzzerTestOneInput_186(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
