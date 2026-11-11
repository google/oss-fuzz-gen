#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_383(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data
    int error_code;
    memcpy(&error_code, data, sizeof(int));

    // Call the function-under-test
    const char *error_message = nc_strerror(error_code);

    // Use the error_message in some way to prevent compiler optimizations
    if (error_message) {
        // Print the error message to a buffer (not to stdout)
        char buffer[256];
        snprintf(buffer, sizeof(buffer), "Error message: %s\n", error_message);
    }

    return 0;
}