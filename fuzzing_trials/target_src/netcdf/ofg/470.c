#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_470(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 0;  // NetCDF file ID
    int varid = 0; // Variable ID

    size_t start[1] = {0};   // Start index for each dimension
    size_t count[1] = {1};   // Count of elements to write for each dimension
    ptrdiff_t stride[1] = {1}; // Stride between elements for each dimension
    ptrdiff_t imap[1] = {1};   // Mapping of elements in memory

    // Ensure the data is not empty and can be cast to long
    if (size < sizeof(long)) {
        return 0;
    }

    // Cast the input data to a long array
    const long *values = (const long *)data;

    // Call the function-under-test
    nc_put_varm_long(ncid, varid, start, count, stride, imap, values);

    return 0;
}