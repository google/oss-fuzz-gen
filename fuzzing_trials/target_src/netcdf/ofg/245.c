#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_245(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for the parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Initialize the parameters
    int ncid = 1;  // Example non-zero value for netCDF file ID
    int varid = 2; // Example non-zero value for variable ID

    // Extract size_t parameters from data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));

    // Extract ptrdiff_t parameter from data
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);

    // Extract unsigned char parameter from data
    const unsigned char *value = (const unsigned char *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Call the function-under-test
    int result = nc_put_vars_uchar(ncid, varid, start, count, stride, value);

    // Return 0 to indicate the fuzzer should continue
    return 0;
}