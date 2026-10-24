#include <string.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include "janet.h"

// Function-under-test
int32_t janet_getendrange(const Janet *array, int32_t len, int32_t lower, int32_t higher);

int LLVMFuzzerTestOneInput_225(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to extract the required parameters
    if (size < sizeof(Janet) + 3 * sizeof(int32_t)) {
        return 0;
    }

    // Initialize the Janet environment
    janet_init();

    // Ensure the data size is sufficient for the array
    int32_t len = (int32_t)data[sizeof(Janet)];
    if (len <= 0 || len > 1) {
        janet_deinit();
        return 0;
    }

    // Initialize the Janet array
    Janet janetArray[1];
    janetArray[0] = janet_wrap_integer((int32_t)data[0]);

    // Extract the parameters from the input data
    int32_t lower = (int32_t)data[sizeof(Janet) + sizeof(int32_t)];
    int32_t higher = (int32_t)data[sizeof(Janet) + 2 * sizeof(int32_t)];

    // Ensure lower and higher are within a valid range
    if (lower < 0 || higher < lower || higher >= len) {
        janet_deinit();
        return 0;
    }

    // Call the function-under-test
    int32_t result = janet_getendrange(janetArray, len, lower, higher);

    // Use the result in some way to avoid compiler optimizations
    (void)result;

    // Cleanup the Janet environment
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

    LLVMFuzzerTestOneInput_225(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
