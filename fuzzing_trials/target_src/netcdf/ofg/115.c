#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    // Initialize parameters for nc_put_vars_ubyte
    int ncid = 0;  // Example netCDF file ID
    int varid = 0; // Example variable ID

    // Ensure the size is sufficient for the parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + 1) {
        return 0;
    }

    // Set up start, count, and stride arrays
    size_t start[1];
    size_t count[1];
    ptrdiff_t stride[1];

    // Extract values from the input data
    memcpy(start, data, sizeof(size_t));
    memcpy(count, data + sizeof(size_t), sizeof(size_t));
    memcpy(stride, data + 2 * sizeof(size_t), sizeof(ptrdiff_t));

    // Ensure count is non-zero to avoid no-op
    if (count[0] == 0) {
        count[0] = 1;
    }

    // Prepare the data array
    const unsigned char *ubData = data + 2 * sizeof(size_t) + sizeof(ptrdiff_t);

    // Call the function-under-test
    int result = nc_put_vars_ubyte(ncid, varid, start, count, stride, ubData);

    // Return 0 to indicate the fuzzer should continue
    return 0;
}