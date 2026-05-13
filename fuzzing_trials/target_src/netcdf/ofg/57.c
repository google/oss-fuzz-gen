#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>

extern int nc_put_vars_longlong(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const long long *value);

int LLVMFuzzerTestOneInput_57(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(long long)) {
        return 0; // Not enough data to fill all parameters
    }

    // Extract parameters from the data
    int ncid;
    int varid;
    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    long long value[1];

    // Copy data into respective variables
    memcpy(&ncid, data, sizeof(int));
    memcpy(&varid, data + sizeof(int), sizeof(int));
    memcpy(start, data + sizeof(int) * 2, sizeof(size_t));
    memcpy(count, data + sizeof(int) * 2 + sizeof(size_t), sizeof(size_t));
    memcpy(stride, data + sizeof(int) * 2 + sizeof(size_t) * 2, sizeof(ptrdiff_t));
    memcpy(value, data + sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t), sizeof(long long));

    // Call the function-under-test
    nc_put_vars_longlong(ncid, varid, start, count, stride, value);

    return 0;
}