#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_188(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract the first 4 bytes of data to use as the ncid
    int ncid = *((int *)data);

    // Allocate memory for the ndims pointer
    int ndims;
    
    // Call the function-under-test
    nc_inq_ndims(ncid, &ndims);

    return 0;
}