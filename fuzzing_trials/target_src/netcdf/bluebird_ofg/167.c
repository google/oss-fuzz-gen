#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_167(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to extract necessary parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(int)) {
        return 0;
    }

    // Initialize parameters
    int ncid = 0;  // Example netCDF ID, replace with actual ID if available
    int varid = 0; // Example variable ID, replace with actual ID if available

    // Extract sizes from the data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);
    const int *value = (const int *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Call the function-under-test
    int result = nc_put_vars_int(ncid, varid, start, count, stride, value);

    // Optional: Print the result for debugging purposes
    printf("nc_put_vars_int result: %d\n", result);

    return 0;
}