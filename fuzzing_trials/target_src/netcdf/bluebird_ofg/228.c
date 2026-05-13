#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "netcdf.h"

// Function-under-test
int nc_put_var1_longlong(int ncid, int varid, const size_t *indexp, const long long *valuep);

int LLVMFuzzerTestOneInput_228(const uint8_t *data, size_t size) {
    // Declare and initialize variables to be used as parameters
    int ncid = 0;  // Example file ID, should be a valid netCDF file ID in real scenarios
    int varid = 0; // Example variable ID, should be a valid variable ID in real scenarios

    // Ensure there's enough data for index and value
    if (size < sizeof(size_t) + sizeof(long long)) {
        return 0;
    }

    // Initialize indexp from the data
    const size_t *indexp = (const size_t *)data;

    // Initialize valuep from the data
    const long long *valuep = (const long long *)(data + sizeof(size_t));

    // Call the function-under-test
    int result = nc_put_var1_longlong(ncid, varid, indexp, valuep);

    // Print result for debugging purposes (optional)
    printf("nc_put_var1_longlong returned: %d\n", result);

    return 0;
}