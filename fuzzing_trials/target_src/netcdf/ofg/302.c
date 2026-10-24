#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_302(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract the required parameters
    if (size < sizeof(size_t) + sizeof(double)) {
        return 0;
    }

    // Extract an integer for the first two parameters
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Extract a size_t for the third parameter
    const size_t *indexp = (const size_t *)(data + 2);

    // Extract a double for the fourth parameter
    const double *valuep = (const double *)(data + 2 + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1_double(ncid, varid, indexp, valuep);

    return 0;
}