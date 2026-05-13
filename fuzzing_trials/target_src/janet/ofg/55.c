#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    // Initialize Janet VM
    janet_init();

    // Create a JanetArray with a size based on the input data
    JanetArray *array = janet_array(size);

    // Populate the JanetArray with Janet values derived from the input data
    for (size_t i = 0; i < size; i++) {
        array->data[i] = janet_wrap_integer(data[i]);
    }
    array->count = size;

    // Call the function-under-test
    Janet result = janet_array_peek(array);

    // Use the result to prevent any compiler optimizations that might
    // remove the call to janet_array_peek
    if (janet_checktype(result, JANET_NIL)) {
        // Do something with the result if needed
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

    LLVMFuzzerTestOneInput_55(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
