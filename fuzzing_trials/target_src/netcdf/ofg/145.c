#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_145(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract two integers
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extract two integers from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    // Allocate memory for the output parameter
    int ndims;
    int *ndimsp = &ndims;

    // Call the function-under-test
    nc_inq_varndims(ncid, varid, ndimsp);

    return 0;
}