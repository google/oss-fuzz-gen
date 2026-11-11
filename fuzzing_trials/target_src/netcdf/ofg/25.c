#include <stdint.h>
#include <stddef.h>

// Function signature for the function-under-test
int nc_show_metadata(int);

// Fuzzing harness for nc_show_metadata
int LLVMFuzzerTestOneInput_25(const uint8_t *data, size_t size) {
    // Ensure that size is non-zero to avoid reading from an empty data buffer
    if (size == 0) {
        return 0;
    }

    // Use the first byte of data to create an integer for nc_show_metadata
    int input_value = (int)data[0];

    // Call the function-under-test with the fuzzed input
    nc_show_metadata(input_value);

    return 0;
}