#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_17(const uint8_t *data, size_t size) {
    // Ensure there is enough data for at least one element for each array parameter
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(long long)) {
        return 0;
    }

    // Initialize parameters for nc_get_vars_longlong
    int ncid = 0; // Example netCDF ID, should be a valid ID in a real scenario
    int varid = 0; // Example variable ID, should be a valid ID in a real scenario

    // Extract sizes from the data
    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    long long values[1];

    // Copy data into the parameters
    size_t offset = 0;
    start[0] = *((const size_t *)(data + offset));
    offset += sizeof(size_t);
    count[0] = *((const size_t *)(data + offset));
    offset += sizeof(size_t);
    stride[0] = *((const ptrdiff_t *)(data + offset));
    offset += sizeof(ptrdiff_t);
    values[0] = *((const long long *)(data + offset));

    // Call the function-under-test
    int result = nc_get_vars_longlong(ncid, varid, start, count, stride, values);

    // Optionally, print the result for debugging purposes
    printf("Result: %d\n", result);

    return 0;
}