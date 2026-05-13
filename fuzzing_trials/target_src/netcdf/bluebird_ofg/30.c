#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_30(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract two integers
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extract two integers from the input data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));

    // Initialize the third parameter for nc_inq_varnatts
    int natts = 0;

    // Call the function-under-test
    nc_inq_varnatts(ncid, varid, &natts);

    return 0;
}