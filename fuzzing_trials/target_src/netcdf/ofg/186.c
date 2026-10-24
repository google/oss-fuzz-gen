#include <stddef.h>
#include <stdint.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_186(const uint8_t *data, size_t size) {
    // Declare and initialize parameters for nc_put_vars
    int ncid = 0;  // Example netCDF file ID
    int varid = 0; // Example variable ID

    // Ensure that size is large enough to extract necessary data
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t)) {
        return 0;
    }

    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 * sizeof(size_t));
    const void *value = (const void *)(data + 2 * sizeof(size_t) + sizeof(ptrdiff_t));

    // Call the function-under-test
    nc_put_vars(ncid, varid, start, count, stride, value);

    return 0;
}