#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Fuzzing harness for janet_lengthv
int LLVMFuzzerTestOneInput_103(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Ensure the data size is sufficient to create a Janet array
    if (size < sizeof(Janet)) {
        janet_deinit();
        return 0;
    }

    // Create a Janet array from the input data
    JanetArray *array = janet_array(size);

    // Fill the Janet array with the input data
    for (size_t i = 0; i < size; i++) {
        array->data[i] = janet_wrap_integer(data[i]);
    }
    array->count = size;

    // Wrap the Janet array into a Janet value
    Janet janet_value = janet_wrap_array(array);

    // Call the function-under-test
    Janet result = janet_lengthv(janet_value);

    // Clean up Janet runtime
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

    LLVMFuzzerTestOneInput_103(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
