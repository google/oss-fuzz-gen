#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Function signature for the function-under-test
int nc_set_default_format(int format, int *result);

int LLVMFuzzerTestOneInput_268(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract two integers
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extract two integers from the input data
    int format = *(const int *)data;
    int resultValue = *((const int *)(data + sizeof(int)));

    // Initialize the result pointer
    int *result = (int *)malloc(sizeof(int));
    if (result == NULL) {
        return 0; // Failed to allocate memory
    }
    *result = resultValue;

    // Call the function-under-test
    nc_set_default_format(format, result);

    // Clean up
    free(result);

    return 0;
}