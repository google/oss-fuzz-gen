#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_327(const uint8_t *data, size_t size) {
    // Initialize the Janet environment
    janet_init();

    // Check if the size of the input data is sufficient to create a Janet array
    if (size < sizeof(JanetArray)) {
        janet_deinit();
        return 0;
    }

    // Create a Janet array from the input data
    JanetArray *array = janet_array(size);

    // Populate the array with data
    for (size_t i = 0; i < size; i++) {
        array->data[i] = janet_wrap_integer((int32_t)data[i]);
    }

    // Wrap the Janet array into a Janet type
    Janet wrapped_array = janet_wrap_array(array);

    // Call the function-under-test
    JanetArray *result = janet_unwrap_array(wrapped_array);

    // Use the result to prevent compiler optimizations from removing the function call
    if (result == NULL) {
        // Handle the case where the result is NULL
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

    LLVMFuzzerTestOneInput_327(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
