#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Ensure there is enough data to work with
    if (size < 2 * sizeof(size_t) + sizeof(int) + 1) {
        return 0;
    }

    // Initialize parameters for nc_put_vara
    int ncid = *(int *)data; // Interpret the first bytes as an integer for ncid
    data += sizeof(int);
    size -= sizeof(int);

    int varid = *(int *)data; // Interpret the next bytes as an integer for varid
    data += sizeof(int);
    size -= sizeof(int);

    size_t start[1];
    size_t count[1];

    // Interpret the next bytes as size_t for start
    start[0] = *(size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Interpret the next bytes as size_t for count
    count[0] = *(size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Use the remaining data as the buffer
    const void *buffer = (const void *)data;

    // Call the function-under-test
    nc_put_vara(ncid, varid, start, count, buffer);

    return 0;
}