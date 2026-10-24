#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_115(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 3) {
        return 0; // Not enough data to proceed
    }

    // Extract the first integer from data to use as the ncid
    int ncid = *(const int *)data;

    // Extract the second integer from data to use as the number of variables
    int nvars = *((const int *)(data + sizeof(int)));

    // Allocate memory for the varids array
    int *varids = (int *)malloc(nvars * sizeof(int));
    if (varids == NULL) {
        return 0; // Memory allocation failed
    }

    // Call the function-under-test
    int result = nc_inq_varids(ncid, &nvars, varids);

    // Clean up
    free(varids);

    return 0;
}