#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_164(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 0;  // Assuming a valid netCDF file id
    int varid = 0; // Assuming a valid variable id
    const size_t ndims = 3; // Assuming 3 dimensions for this example
    size_t start[ndims];
    size_t count[ndims];
    ptrdiff_t stride[ndims];
    ptrdiff_t imap[ndims];
    short values[ndims]; // Array to hold short values

    // Ensure size is sufficient for our needs
    if (size < ndims * (sizeof(size_t) + sizeof(ptrdiff_t) + sizeof(short))) {
        return 0;
    }

    // Fill start, count, stride, imap, and values arrays with data
    for (size_t i = 0; i < ndims; i++) {
        start[i] = (size_t)data[i] % 10; // Modulo to ensure reasonable values
        count[i] = (size_t)data[i + ndims] % 10;
        stride[i] = (ptrdiff_t)data[i + 2 * ndims] % 10;
        imap[i] = (ptrdiff_t)data[i + 3 * ndims] % 10;
        values[i] = (short)data[i + 4 * ndims];
    }

    // Call the function-under-test
    nc_put_varm_short(ncid, varid, start, count, stride, imap, values);

    return 0;
}