#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_541(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract meaningful parameters
    if (size < 6 * sizeof(size_t) + sizeof(ptrdiff_t) * 4 + sizeof(signed char)) {
        return 0;
    }

    // Initialize parameters
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Extract size_t arrays from data
    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + 2 * sizeof(size_t));
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + 2 + 2 * sizeof(size_t) + sizeof(ptrdiff_t));

    // Extract signed char array from data
    const signed char *value = (const signed char *)(data + 2 + 2 * sizeof(size_t) + 2 * sizeof(ptrdiff_t));

    // Call the function-under-test
    int result = nc_put_varm_schar(ncid, varid, start, count, stride, imap, value);

    // Optionally print the result for debugging purposes
    printf("nc_put_varm_schar result: %d\n", result);

    return 0;
}