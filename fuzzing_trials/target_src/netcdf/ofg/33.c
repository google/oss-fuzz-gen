#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

extern int nc_get_vars_long(int, int, const size_t *, const size_t *, const ptrdiff_t *, long *);

int LLVMFuzzerTestOneInput_33(const uint8_t *data, size_t size) {
    // Ensure there is enough data for at least one element of each parameter
    if (size < 2 * sizeof(size_t) + sizeof(ptrdiff_t) + sizeof(long)) {
        return 0;
    }

    // Initialize parameters
    int ncid = (int)data[0];
    int varid = (int)data[1];

    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    long value[1];

    // Populate the parameters with data from the input
    start[0] = (size_t)data[2];
    count[0] = (size_t)data[3];
    stride[0] = (ptrdiff_t)data[4];
    value[0] = (long)data[5];

    // Call the function-under-test
    nc_get_vars_long(ncid, varid, start, count, stride, value);

    return 0;
}