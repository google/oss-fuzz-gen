#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

extern int nc_get_vars_schar(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, signed char *data);

int LLVMFuzzerTestOneInput_292(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value

    // Check if the size is sufficient to extract values for start, count, and stride
    if (size < 3 * sizeof(size_t) + 3 * sizeof(ptrdiff_t) + 10) {
        return 0;
    }

    // Initialize start, count, and stride arrays
    size_t start[3];
    size_t count[3];
    ptrdiff_t stride[3];

    // Extract values from data
    memcpy(start, data, sizeof(size_t) * 3);
    memcpy(count, data + sizeof(size_t) * 3, sizeof(size_t) * 3);
    memcpy(stride, data + 2 * sizeof(size_t) * 3, sizeof(ptrdiff_t) * 3);

    // Initialize data buffer
    signed char buffer[10];
    memcpy(buffer, data + 2 * sizeof(size_t) * 3 + 3 * sizeof(ptrdiff_t), 10);

    // Call the function-under-test
    nc_get_vars_schar(ncid, varid, start, count, stride, buffer);

    return 0;
}