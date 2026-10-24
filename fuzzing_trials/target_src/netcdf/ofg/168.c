#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_168(const uint8_t *data, size_t size) {
    // Ensure there's enough data for the required parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(short)) {
        return 0;
    }

    // Initialize parameters
    int ncid = *(int *)data;
    int varid = *(int *)(data + sizeof(int));

    const size_t *start = (const size_t *)(data + sizeof(int) * 2);
    const size_t *count = (const size_t *)(data + sizeof(int) * 2 + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);
    const short *value = (const short *)(data + sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Call the function-under-test
    nc_put_vars_short(ncid, varid, start, count, stride, value);

    return 0;
}