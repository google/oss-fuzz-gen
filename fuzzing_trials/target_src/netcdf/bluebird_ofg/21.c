#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Function-under-test declaration
int nc_set_default_format(int format, int *result);

// Fuzzing harness
int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2) {
        return 0; // Not enough data to extract two integers
    }

    // Extract two integers from the input data
    int format = *((int *)data);
    int result_value = *((int *)(data + sizeof(int)));

    // Initialize a pointer with a non-NULL value
    int *result = &result_value;

    // Call the function-under-test
    nc_set_default_format(format, result);

    return 0;
}