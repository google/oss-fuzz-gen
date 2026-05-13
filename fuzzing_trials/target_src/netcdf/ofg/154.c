#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_154(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Initialize variables
    int ncid = 0; // Assume a valid netCDF file identifier
    int varid = 0; // Assume a valid variable identifier

    // Extract size_t values from data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));

    // Extract ptrdiff_t value from data
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 * sizeof(size_t));

    // Extract unsigned int value from data
    const unsigned int *values = (const unsigned int *)(data + 2 * sizeof(size_t) + sizeof(ptrdiff_t));

    // Call the function-under-test
    nc_put_vars_uint(ncid, varid, start, count, stride, values);

    return 0;
}