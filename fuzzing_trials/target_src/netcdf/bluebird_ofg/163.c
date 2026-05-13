#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_163(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for nc_put_vars_ushort
    int ncid = 0; // Assuming a valid netCDF file identifier
    int varid = 0; // Assuming a valid variable identifier

    // Ensure size is sufficient to extract necessary data
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(unsigned short)) {
        return 0;
    }

    // Extract count and start from data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));

    // Extract stride from data
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 * sizeof(size_t));

    // Extract value from data
    const unsigned short *value = (const unsigned short *)(data + 2 * sizeof(size_t) + sizeof(ptrdiff_t));

    // Call the function-under-test
    nc_put_vars_ushort(ncid, varid, start, count, stride, value);

    return 0;
}