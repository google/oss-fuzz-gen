#include <stdint.h>
#include <stddef.h>
#include <janet.h>

int LLVMFuzzerTestOneInput_255(const uint8_t *data, size_t size) {
    // Initialize Janet runtime
    janet_init();

    // Ensure that the data size is sufficient to extract an index
    if (size < sizeof(int32_t)) {
        return 0;
    }

    // Create a Janet array with some test values
    JanetArray *array = janet_array(10);
    for (int i = 0; i < 10; i++) {
        array->data[i] = janet_wrap_integer(i);
    }
    array->count = 10;

    // Wrap the array in a Janet object
    Janet wrapped_array = janet_wrap_array(array);

    // Extract an index from the input data
    int32_t index = *((int32_t *)data);

    // Call the function-under-test
    Janet result = janet_getindex(wrapped_array, index);

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

    LLVMFuzzerTestOneInput_255(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
