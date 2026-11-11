#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_168(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(short)) {
        return 0;
    }

    // Initialize parameters for nc_put_vars_short
    int ncid = 0;  // Example netCDF file ID
    int varid = 0; // Example variable ID

    // Define start, count, and stride arrays
    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    short value[1];

    // Populate the arrays with data from the input
    start[0] = (size_t)data[0];
    count[0] = (size_t)data[1];
    stride[0] = (ptrdiff_t)data[2];
    value[0] = (short)data[3];

    // Call the function-under-test
    int result = nc_put_vars_short(ncid, varid, start, count, stride, value);

    // Check the result (for debugging purposes)
    if (result != NC_NOERR) {
        fprintf(stderr, "nc_put_vars_short failed: %s\n", nc_strerror(result));
    }

    return 0;
}