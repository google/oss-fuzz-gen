#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_252(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(float)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)data;
    data += sizeof(int);
    int varid = *(const int *)data;
    data += sizeof(int);

    // Assume a fixed number of dimensions for simplicity
    size_t ndims = 1;
    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];
    float value[1];

    start[0] = *(const size_t *)data;
    data += sizeof(size_t);
    count[0] = *(const size_t *)data;
    data += sizeof(size_t);
    stride[0] = *(const ptrdiff_t *)data;
    data += sizeof(ptrdiff_t);
    value[0] = *(const float *)data;

    // Call the function-under-test
    nc_put_vars_float(ncid, varid, start, count, stride, value);

    return 0;
}