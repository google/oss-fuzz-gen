#include <stdint.h>
#include <stddef.h>

// Declaration of the function-under-test
int nc_abort(int);

// Fuzzing harness for the function nc_abort
int LLVMFuzzerTestOneInput_240(const uint8_t *data, size_t size) {
    // Ensure there is enough data to construct an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int input_value;
    // Copy the data into the integer, assuming little-endian format
    input_value = *(const int *)data;

    // Call the function-under-test with the extracted integer
    nc_abort(input_value);

    return 0;
}