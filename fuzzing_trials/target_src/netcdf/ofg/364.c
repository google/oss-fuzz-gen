#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_364(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient to extract two integers
    if (size < 2 * sizeof(int)) {
        return 0;
    }

    // Extract two integers from the input data
    int ncid = *((const int *)data);
    int varid = *((const int *)(data + sizeof(int)));

    // Allocate memory for the output parameter
    int natts;
    
    // Call the function-under-test
    nc_inq_varnatts(ncid, varid, &natts);

    return 0;
}