#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_116(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid = 1; // Example non-zero file ID
    int varid = 1; // Example non-zero variable ID

    // Ensure size is large enough to extract indices and strides
    if (size < 3 * sizeof(size_t) + sizeof(ptrdiff_t)) {
        return 0;
    }

    // Use the data to create start, count, and stride arrays
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 * sizeof(size_t));
    const unsigned char *value = (const unsigned char *)(data + 3 * sizeof(size_t));

    // Call the function under test
    nc_put_vars_ubyte(ncid, varid, start, count, stride, value);

    return 0;
}