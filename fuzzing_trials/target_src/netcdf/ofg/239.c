#include <stdint.h>
#include <stdlib.h>

// Function-under-test
int nc_abort(int);

// Fuzzing harness
int LLVMFuzzerTestOneInput_239(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Ensure there is enough data to interpret as an int
    }

    // Interpret the first few bytes of the data as an integer
    int input_value = *((int *)data);

    // Call the function-under-test
    nc_abort(input_value);

    return 0;
}