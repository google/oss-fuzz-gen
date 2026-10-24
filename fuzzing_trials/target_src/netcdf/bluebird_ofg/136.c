#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_136(const uint8_t *data, size_t size) {
    // Initialize variables
    int ncid = 0; // Assuming a valid netCDF file ID
    int varid = 0; // Assuming a valid variable ID

    // Define dimensions for the netCDF variable
    size_t start[2] = {0, 0}; // Start at the beginning of the dimensions
    size_t count[2] = {1, 1}; // Assuming a 2D variable with count of 1 for each dimension
    ptrdiff_t stride[2] = {1, 1}; // No stride, access every element
    ptrdiff_t imap[2] = {1, 1}; // No mapping, access every element

    // Ensure the data size matches the expected size for the variable
    if (size < sizeof(unsigned char)) {
        return 0;
    }

    // Call the function-under-test
    int result = nc_put_varm_ubyte(ncid, varid, start, count, stride, imap, (const unsigned char *)data);

    return 0;
}