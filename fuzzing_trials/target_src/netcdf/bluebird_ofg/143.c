#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_143(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2 + sizeof(signed char)) {
        return 0;
    }

    // Initialize variables
    int ncid = 0;  // Assuming a valid netCDF file ID for fuzzing
    int varid = 0; // Assuming a valid variable ID for fuzzing

    // Extract values from the input data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));
    const signed char *value = (const signed char *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2);

    // Call the function-under-test
    int result = nc_put_varm_schar(ncid, varid, start, count, stride, imap, value);

    // Use the result to avoid compiler optimizations that may remove the function call
    if (result != NC_NOERR) {
        fprintf(stderr, "Error: %s\n", nc_strerror(result));
    }

    return 0;
}