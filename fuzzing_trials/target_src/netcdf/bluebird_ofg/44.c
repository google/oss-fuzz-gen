#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include "netcdf.h"

// Function-under-test
int nc_inq_unlimdims(int ncid, int *ndims, int *unlimdimids);

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for the function
    int ncid = 0; // Using 0 as a placeholder, as actual value should come from a valid NetCDF file
    int ndims = 0;
    int unlimdimids[10]; // Assuming a maximum of 10 unlimited dimensions for testing

    // Call the function-under-test
    int result = nc_inq_unlimdims(ncid, &ndims, unlimdimids);

    // Print the result for debugging purposes
    printf("Result: %d, Number of unlimited dimensions: %d\n", result, ndims);

    return 0;
}