#include <stdint.h>
#include <stddef.h>
#include <janet.h>

// Fuzzing harness for janet_getcfunction
int LLVMFuzzerTestOneInput_259(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to create a Janet array
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Create a Janet array from the input data
    Janet *janet_array = (Janet *)data;
    int32_t index = 0;

    // Ensure the Janet array is properly initialized
    JanetType type = janet_type(janet_array[index]);
    if (type != JANET_FUNCTION && type != JANET_CFUNCTION) {
        return 0;
    }

    // Call the function-under-test
    JanetCFunction result = janet_getcfunction(janet_array, index);

    // Use the result in some way to prevent compiler optimizations from removing the call
    if (result != NULL) {
        // Call the function to ensure it is used
        result(NULL, 0);
    }

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

    LLVMFuzzerTestOneInput_259(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
