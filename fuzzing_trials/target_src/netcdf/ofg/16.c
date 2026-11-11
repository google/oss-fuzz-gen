#include <stdint.h>
#include <stddef.h>

// Function-under-test
int nc_sync(int);

// Fuzzing harness
int LLVMFuzzerTestOneInput_16(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int input_value = 0;
    for (size_t i = 0; i < sizeof(int); ++i) {
        input_value |= (data[i] << (i * 8));
    }

    // Call the function-under-test
    nc_sync(input_value);

    return 0;
}