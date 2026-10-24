#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_241(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 0; // NetCDF file ID, typically obtained from nc_open or nc_create
    int varid = 0; // Variable ID, typically obtained from nc_inq_varid
    size_t index[1] = {0}; // Index to specify the position in the variable
    void *value = NULL; // Pointer to the data to be written

    // Ensure size is large enough to extract necessary data
    if (size < sizeof(int) + sizeof(int) + sizeof(size_t) + sizeof(double)) {
        return 0;
    }

    // Extract ncid and varid from the input data
    ncid = *((int *)data);
    varid = *((int *)(data + sizeof(int)));

    // Extract index from the input data
    index[0] = *((size_t *)(data + 2 * sizeof(int)));

    // Allocate memory for value and copy data from input
    value = malloc(sizeof(double));
    if (value == NULL) {
        return 0;
    }
    *((double *)value) = *((double *)(data + 2 * sizeof(int) + sizeof(size_t)));

    // Call the function-under-test
    nc_put_var1(ncid, varid, index, value);

    // Free allocated memory
    free(value);

    return 0;
}