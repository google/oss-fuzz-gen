#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_138(const uint8_t *data, size_t size) {
    // Ensure there is enough data for all parameters
    if (size < sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2 + sizeof(long)) {
        return 0;
    }

    // Initialize parameters
    int ncid = 0;  // NetCDF file ID, assuming a valid file ID
    int varid = 0; // Variable ID, assuming a valid variable ID

    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t) * 1);
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 1);
    const long *value = (const long *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2);

    // Call the function-under-test
    int result = nc_put_varm_long(ncid, varid, start, count, stride, imap, value);

    // Print result for debugging purposes
    printf("nc_put_varm_long result: %d\n", result);

    return 0;
}