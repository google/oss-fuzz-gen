#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_97(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract necessary parameters
    if (size < sizeof(int) * 3) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    data += sizeof(int);
    size -= sizeof(int);

    int ndims = *((int *)data);
    data += sizeof(int);
    size -= sizeof(int);

    int include_parents = *((int *)data);
    data += sizeof(int);
    size -= sizeof(int);

    // Allocate memory for dimids array
    int *dimids = (int *)malloc(ndims * sizeof(int));
    if (dimids == NULL) {
        return 0;
    }

    // Call the function-under-test
    nc_inq_dimids(ncid, dimids, &ndims, include_parents);

    // Free allocated memory
    free(dimids);

    return 0;
}