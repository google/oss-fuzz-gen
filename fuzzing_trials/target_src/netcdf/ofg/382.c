#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <netcdf.h>

// Function-under-test
const char *nc_strerror(int err);

// Fuzzing harness
int LLVMFuzzerTestOneInput_382(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract an integer value
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int err = *(const int *)data;

    // Call the function-under-test
    const char *error_message = nc_strerror(err);

    // Print the error message (optional, for debugging purposes)
    printf("Error message: %s\n", error_message);

    return 0;
}