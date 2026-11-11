#include <stdint.h>
#include <stddef.h>

// Function-under-test declaration
int nc_show_metadata(int);

// Fuzzing harness
int LLVMFuzzerTestOneInput_24(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int input_value = 0;
    for (size_t i = 0; i < sizeof(int); ++i) {
        input_value |= (data[i] << (i * 8));
    }

    // Call the function-under-test
    nc_show_metadata(input_value);

    return 0;
}