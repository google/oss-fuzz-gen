#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_vara_ulonglong(int ncid, int varid, const size_t *start, const size_t *count, unsigned long long *value);

int LLVMFuzzerTestOneInput_150(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function-under-test
    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value
    size_t start[2] = {0, 0}; // Example start indices for a 2D variable
    size_t count[2] = {1, 1}; // Example count for a 2D variable
    unsigned long long value[1] = {0}; // Buffer to store the result

    // Ensure that the size is sufficient to interpret as indices and counts
    if (size < sizeof(size_t) * 4) {
        return 0;
    }

    // Populate start and count arrays with data from the fuzzer input
    start[0] = ((const size_t *)data)[0];
    start[1] = ((const size_t *)data)[1];
    count[0] = ((const size_t *)data)[2];
    count[1] = ((const size_t *)data)[3];

    // Call the function-under-test
    nc_get_vara_ulonglong(ncid, varid, start, count, value);

    return 0;
}