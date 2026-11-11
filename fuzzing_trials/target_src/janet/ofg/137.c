#include <stdint.h>
#include <stdlib.h>
#include <janet.h>

// Remove 'extern "C"' as it is not needed in C code
int LLVMFuzzerTestOneInput_137(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet)) {
        return 0;
    }

    // Initialize Janet
    janet_init();

    // Prepare a Janet array to hold the input data
    Janet *janetArray = (Janet *)malloc(sizeof(Janet) * size);
    if (!janetArray) {
        return 0;
    }

    // Copy data into the Janet array
    for (size_t i = 0; i < size; ++i) {
        janetArray[i] = janet_wrap_integer(data[i]);
    }

    // Use a valid index within the bounds of the array
    int32_t index = size > 1 ? 1 : 0;

    // Call the function-under-test
    JanetFunction *result = janet_getfunction(janetArray, index);

    // Cleanup
    free(janetArray);

    // Deinitialize Janet
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

    LLVMFuzzerTestOneInput_137(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
