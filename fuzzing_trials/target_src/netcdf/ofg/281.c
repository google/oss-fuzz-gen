#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_281(const uint8_t *data, size_t size) {
    // Check if the size is sufficient for our parameters
    if (size < sizeof(size_t) * 2 + sizeof(float)) {
        return 0;
    }

    // Initialize parameters for nc_put_vara_float
    int ncid = 0; // Example netCDF ID, should be a valid ID in a real scenario
    int varid = 0; // Example variable ID, should be a valid ID in a real scenario

    // Extract start and count from data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));

    // Extract float data
    const float *fp = (const float *)(data + sizeof(size_t) * 2);

    // Call the function-under-test
    int result = nc_put_vara_float(ncid, varid, start, count, fp);

    // Print the result for debugging purposes
    printf("nc_put_vara_float result: %d\n", result);

    return 0;
}