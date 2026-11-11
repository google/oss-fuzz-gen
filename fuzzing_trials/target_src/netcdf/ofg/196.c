#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assuming the function is part of a library, include the necessary header
#include <netcdf.h>

int LLVMFuzzerTestOneInput_196(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the input data for the first parameter
    int ncid = *(const int *)data;

    // Allocate memory for the second and third parameters
    int *ndims = (int *)malloc(sizeof(int));
    int *unlimdimids = (int *)malloc(sizeof(int));

    // Initialize the allocated memory to avoid passing NULL
    if (ndims != NULL) {
        *ndims = 0;
    }
    if (unlimdimids != NULL) {
        *unlimdimids = 0;
    }

    // Call the function-under-test
    nc_inq_unlimdims(ncid, ndims, unlimdimids);

    // Free the allocated memory
    free(ndims);
    free(unlimdimids);

    return 0;
}