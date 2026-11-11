#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_139(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(int)) {
        return 0;
    }

    int ncid = 0; // NetCDF file ID (assuming a valid ID for fuzzing purposes)
    int varid = 0; // Variable ID (assuming a valid ID for fuzzing purposes)

    // Extracting values from the input data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 * sizeof(size_t));
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + 2 * sizeof(size_t) + sizeof(ptrdiff_t));
    const int *value = (const int *)(data + 2 * sizeof(size_t) + 2 * sizeof(ptrdiff_t));

    // Call the function-under-test
    int result = nc_put_varm_int(ncid, varid, start, count, stride, imap, value);

    // You can optionally print the result for debugging purposes
    printf("nc_put_varm_int result: %d\n", result);

    return 0;
}