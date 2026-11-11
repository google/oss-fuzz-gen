#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// Function signature to be fuzzed
int nc_put_vara_float(int ncid, int varid, const size_t *start, const size_t *count, const float *fp);

int LLVMFuzzerTestOneInput_280(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value

    // Ensure the size is sufficient for start and count arrays
    if (size < 4 * sizeof(size_t)) {
        return 0;
    }

    // Initialize start and count arrays
    size_t start[2];
    size_t count[2];
    start[0] = (size_t)data[0];
    start[1] = (size_t)data[1];
    count[0] = (size_t)data[2];
    count[1] = (size_t)data[3];

    // Ensure the size is sufficient for at least one float
    if (size < 4 * sizeof(size_t) + sizeof(float)) {
        return 0;
    }

    // Initialize the float array
    const float *fp = (const float *)(data + 4 * sizeof(size_t));

    // Call the function-under-test
    nc_put_vara_float(ncid, varid, start, count, fp);

    return 0;
}