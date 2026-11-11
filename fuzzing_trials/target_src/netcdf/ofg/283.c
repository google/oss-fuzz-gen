#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h> // Include the NetCDF header for function declarations

// Mock function signature for illustration purposes
// This would normally be provided by the NetCDF library
// int nc_get_var1_double(int ncid, int varid, const size_t *indexp, double *ip);

int LLVMFuzzerTestOneInput_283(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to extract required parameters
    if (size < sizeof(int) * 2 + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    size_t index = *((size_t *)(data + 2 * sizeof(int)));
    
    // Allocate memory for the double output
    double ip;
    
    // Call the function-under-test
    nc_get_var1_double(ncid, varid, &index, &ip);

    return 0;
}