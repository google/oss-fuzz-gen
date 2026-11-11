#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_487(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 0;  // NetCDF file ID, assuming 0 as a placeholder
    int num_vars = 0; // Placeholder for the number of variables
    int *varids = NULL; // Placeholder for variable IDs

    // Ensure size is sufficient to read at least one int
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data for ncid
    ncid = *(int *)data;
    
    // Allocate memory for varids based on size
    varids = (int *)malloc(size * sizeof(int));
    if (varids == NULL) {
        return 0;
    }

    // Call the function-under-test
    int result = nc_inq_varids(ncid, &num_vars, varids);

    // Clean up
    free(varids);

    return 0;
}