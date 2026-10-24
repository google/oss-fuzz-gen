#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test declaration
int nc_get_vars_float(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, float *data);

int LLVMFuzzerTestOneInput_378(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 1; // Example non-zero value
    int varid = 2; // Example non-zero value

    // Ensure size is sufficient for at least one element for start, count, stride, and data
    if (size < 3 * sizeof(size_t) + sizeof(ptrdiff_t) + sizeof(float)) {
        return 0;
    }

    // Initialize start, count, stride, and data
    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    float data_out[1];

    // Copy data from fuzz input
    memcpy(start, data, sizeof(size_t));
    memcpy(count, data + sizeof(size_t), sizeof(size_t));
    memcpy(stride, data + 2 * sizeof(size_t), sizeof(ptrdiff_t));
    memcpy(data_out, data + 2 * sizeof(size_t) + sizeof(ptrdiff_t), sizeof(float));

    // Ensure count is non-zero to avoid no-operation
    if (count[0] == 0) {
        count[0] = 1;
    }

    // Call the function-under-test
    nc_get_vars_float(ncid, varid, start, count, stride, data_out);

    return 0;
}