#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "netcdf.h"

extern int nc_put_vara_short(int ncid, int varid, const size_t *start, const size_t *count, const short *value);

int LLVMFuzzerTestOneInput_183(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for our needs
    if (size < sizeof(size_t) * 2 + sizeof(short)) {
        return 0;
    }

    // Extract values from data
    int ncid = (int)data[0];
    int varid = (int)data[1];
    
    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));
    const short *value = (const short *)(data + 2 + sizeof(size_t) * 2);

    // Call the function-under-test
    nc_put_vara_short(ncid, varid, start, count, value);

    return 0;
}