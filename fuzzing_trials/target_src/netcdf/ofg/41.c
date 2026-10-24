#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_41(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(int)) {
        return 0;
    }

    // Extract parameters from the data
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

    int value[1];
    value[0] = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Call the function-under-test
    nc_put_vara_int(ncid, varid, start, count, value);

    return 0;
}