#include <sys/stat.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "janet.h"

// Function prototype for janet_getstartrange
extern int32_t janet_getstartrange(const Janet *, int32_t, int32_t, int32_t);

int LLVMFuzzerTestOneInput_483(const uint8_t *data, size_t size) {
    if (size < sizeof(Janet) + 3 * sizeof(int32_t)) {
        return 0; // Not enough data to fill the parameters
    }

    // Calculate the number of Janet elements we can safely copy
    size_t janet_array_size = (size - 3 * sizeof(int32_t)) / sizeof(Janet);
    if (janet_array_size == 0) {
        return 0; // Not enough data for even one Janet element
    }

    // Initialize Janet array
    Janet *janet_array = (Janet *)malloc(janet_array_size * sizeof(Janet));
    if (!janet_array) {
        return 0; // Failed to allocate memory
    }

    // Copy data into the Janet array
    memcpy(janet_array, data, janet_array_size * sizeof(Janet));

    // Extract int32_t values from the data
    int32_t start = *(int32_t *)(data + janet_array_size * sizeof(Janet));
    int32_t end = *(int32_t *)(data + janet_array_size * sizeof(Janet) + sizeof(int32_t));
    int32_t length = *(int32_t *)(data + janet_array_size * sizeof(Janet) + 2 * sizeof(int32_t));

    // Ensure that start, end, and length are within valid bounds
    if (start < 0 || end < start || length < 0 || end >= janet_array_size) {
        free(janet_array);
        return 0;
    }

    // Call the function-under-test
    int32_t result = janet_getstartrange(janet_array, start, end, length);

    // Use the result (in a real fuzzing scenario, you might check for crashes or unexpected behavior)
    (void)result; // Suppress unused variable warning

    // Free the allocated memory
    free(janet_array);

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

    LLVMFuzzerTestOneInput_483(data + 2, (size_t)(size - 2));

    free(data);
    fclose(f);
    return 0;
}
#endif
