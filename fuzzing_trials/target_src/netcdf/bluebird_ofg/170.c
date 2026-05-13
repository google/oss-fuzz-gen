#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_170(const uint8_t *data, size_t size) {
    // Ensure there is enough data to initialize all parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Initialize parameters
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    int varid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    size_t start[1];
    start[0] = *(const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    size_t count[1];
    count[0] = *(const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    ptrdiff_t stride[1];
    stride[0] = *(const ptrdiff_t *)data;
    data += sizeof(ptrdiff_t);
    size -= sizeof(ptrdiff_t);

    unsigned char *values = (unsigned char *)malloc(size);
    if (values == NULL) {
        return 0;
    }
    memcpy(values, data, size);

    // Call the function-under-test
    nc_put_vars_uchar(ncid, varid, start, count, stride, values);

    // Clean up
    free(values);

    return 0;
}