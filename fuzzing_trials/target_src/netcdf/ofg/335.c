#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_335(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 1;  // Assuming a valid non-zero file ID for testing
    int varid = 1; // Assuming a valid non-zero variable ID for testing

    // Define dimensions for testing
    size_t ndims = 2; // Example with 2 dimensions
    size_t start[2] = {0, 0}; // Starting indices for each dimension
    size_t count[2] = {1, 1}; // Count of elements for each dimension

    // Ensure the data size is sufficient for at least one double
    if (size < sizeof(double)) {
        return 0;
    }

    // Allocate space for double values and copy from input data
    double *values = (double *)malloc(sizeof(double) * count[0] * count[1]);
    if (values == NULL) {
        return 0;
    }

    for (size_t i = 0; i < count[0] * count[1]; i++) {
        values[i] = ((double *)data)[i % (size / sizeof(double))];
    }

    // Call the function-under-test
    nc_put_vara_double(ncid, varid, start, count, values);

    // Clean up
    free(values);

    return 0;
}