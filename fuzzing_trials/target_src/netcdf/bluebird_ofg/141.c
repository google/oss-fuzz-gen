#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_141(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid = 0; // Example netCDF file ID
    int varid = 0; // Example variable ID

    // Ensure size is sufficient for the required parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(unsigned char)) {
        return 0;
    }

    // Initialize start and count arrays
    size_t start[2] = {0, 0};
    size_t count[2] = {1, 1};

    // Initialize stride and imap arrays
    ptrdiff_t stride[2] = {1, 1};
    ptrdiff_t imap[2] = {1, 1};

    // Initialize value array
    unsigned char value = data[0]; // Use the first byte of data as an example value

    // Call the function-under-test
    nc_put_varm_uchar(ncid, varid, start, count, stride, imap, &value);

    return 0;
}