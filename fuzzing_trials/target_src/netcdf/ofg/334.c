#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_334(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(size_t) * 2 + sizeof(double)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = (int)data[0]; // Use the first byte as ncid
    int varid = (int)data[1]; // Use the second byte as varid

    // Calculate the number of dimensions
    size_t num_dims = (size - 2) / (sizeof(size_t) * 2 + sizeof(double));

    // Allocate memory for start and count arrays
    size_t *start = (size_t *)malloc(num_dims * sizeof(size_t));
    size_t *count = (size_t *)malloc(num_dims * sizeof(size_t));

    // Fill start and count arrays
    for (size_t i = 0; i < num_dims; i++) {
        start[i] = ((size_t *)(data + 2))[i];
        count[i] = ((size_t *)(data + 2))[num_dims + i];
    }

    // Allocate memory for the values array
    double *values = (double *)malloc(num_dims * sizeof(double));

    // Fill the values array
    for (size_t i = 0; i < num_dims; i++) {
        values[i] = ((double *)(data + 2 + 2 * num_dims * sizeof(size_t)))[i];
    }

    // Call the function-under-test
    nc_put_vara_double(ncid, varid, start, count, values);

    // Free allocated memory
    free(start);
    free(count);
    free(values);

    return 0;
}