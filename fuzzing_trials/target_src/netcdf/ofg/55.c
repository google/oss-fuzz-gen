#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Mock function for demonstration purposes
int nc_get_vara_double_55(int ncid, int varid, const size_t *start, const size_t *count, double *data) {
    // Implementation of the function goes here
    return 0; // Return success for demonstration
}

int LLVMFuzzerTestOneInput_55(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(double)) {
        return 0; // Not enough data to proceed
    }

    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value

    size_t start[1];
    size_t count[1];
    double buffer[1];

    // Initialize start and count from the input data
    start[0] = *((const size_t *)data);
    count[0] = *((const size_t *)(data + sizeof(size_t)));

    // Initialize buffer with some data from the input
    buffer[0] = *((const double *)(data + 2 * sizeof(size_t)));

    // Call the function-under-test
    nc_get_vara_double_55(ncid, varid, start, count, buffer);

    return 0;
}