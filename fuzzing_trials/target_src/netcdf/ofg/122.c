#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_122(const uint8_t *data, size_t size) {
    // Ensure there is enough data for all parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(int)) {
        return 0;
    }

    // Initialize parameters
    int ncid = 1;  // Example netCDF file ID
    int varid = 1; // Example variable ID

    // Extract parameters from input data
    size_t start[1], count[1];
    ptrdiff_t stride[1], imap[1];
    int value[1];

    start[0] = *((const size_t *)data) % 10; // Limit to a small range
    count[0] = *((const size_t *)(data + sizeof(size_t))) % 10 + 1; // Avoid zero count
    stride[0] = *((const ptrdiff_t *)(data + sizeof(size_t) * 2)) % 10 + 1; // Avoid zero stride
    imap[0] = *((const ptrdiff_t *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t))) % 10 + 1; // Avoid zero imap
    value[0] = *((const int *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2));

    // Call the function-under-test
    nc_put_varm_int(ncid, varid, start, count, stride, imap, value);

    return 0;
}