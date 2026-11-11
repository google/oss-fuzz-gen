#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Function prototype for the function-under-test
int nc_put_vara_ulonglong(int ncid, int varid, const size_t *start, const size_t *count, const unsigned long long *op);

// Fuzzer entry point
int LLVMFuzzerTestOneInput_148(const uint8_t *data, size_t size) {
    // Define and initialize variables for the function-under-test
    int ncid = 1;  // Example value, should be a valid netCDF file ID
    int varid = 1; // Example value, should be a valid variable ID

    // Ensure there is enough data to initialize start and count arrays
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

    // Ensure there is enough data for the op array
    if (size < 4 * sizeof(size_t) + 2 * sizeof(unsigned long long)) {
        return 0;
    }

    // Initialize op array
    unsigned long long op[2];
    op[0] = (unsigned long long)data[4];
    op[1] = (unsigned long long)data[5];

    // Call the function-under-test
    nc_put_vara_ulonglong(ncid, varid, start, count, op);

    return 0;
}