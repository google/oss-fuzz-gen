#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Assume the function is declared in some header file included here
// #include "netcdf_filter.h"

int nc_inq_var_filter(int ncid, int varid, unsigned int *idp, size_t *nparamsp, unsigned int *params);

int LLVMFuzzerTestOneInput_39(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(unsigned int) + sizeof(size_t) + sizeof(unsigned int)) {
        return 0; // Not enough data to fill all parameters
    }

    // Initialize parameters
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));
    unsigned int idp = *(const unsigned int *)(data + 2 * sizeof(int));
    size_t nparams = *(const size_t *)(data + 2 * sizeof(int) + sizeof(unsigned int));
    unsigned int params = *(const unsigned int *)(data + 2 * sizeof(int) + sizeof(unsigned int) + sizeof(size_t));

    // Call the function-under-test
    nc_inq_var_filter(ncid, varid, &idp, &nparams, &params);

    return 0;
}