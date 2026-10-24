#include <stdint.h>
#include <stddef.h>

// Function-under-test declaration
int nc_redef(int);

// Fuzzing harness for nc_redef
int LLVMFuzzerTestOneInput_53(const uint8_t *data, size_t size) {
    // Ensure there's at least one byte to convert to an int
    if (size < sizeof(int)) {
        return 0;
    }

    // Convert the first few bytes of the input data to an int
    int input_value = 0;
    for (size_t i = 0; i < sizeof(int); ++i) {
        input_value |= (int)data[i] << (i * 8);
    }

    // Call the function-under-test
    nc_redef(input_value);

    return 0;
}