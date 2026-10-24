#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_135(const uint8_t *data, size_t size) {
    // Define and initialize parameters for nc_put_vars_long_135
    int ncid = 0; // NetCDF file ID, using a dummy value
    int varid = 0; // Variable ID, using a dummy value

    // Ensure size is large enough to extract necessary parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(long)) {
        return 0;
    }

    // Extract start, count, stride, and value from the data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);
    const long *value = (const long *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Call the function-under-test
    int result = nc_put_vars_long(ncid, varid, start, count, stride, value);

    // Output the result for debugging purposes
    printf("nc_put_vars_long_135 returned: %d\n", result);

    return 0;
}