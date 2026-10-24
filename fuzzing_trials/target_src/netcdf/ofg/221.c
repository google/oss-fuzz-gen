#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>

// Assuming the function is part of a library we are linking against.
extern int nc_inq_dimids(int ncid, int *ndimsp, int *dimids, int include_parents);

int LLVMFuzzerTestOneInput_221(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 3) {
        // Not enough data to extract the necessary integers
        return 0;
    }

    // Extract integers from the input data
    int ncid = *((int *)data);
    int ndims;
    int *dimids = (int *)(data + sizeof(int));
    int include_parents = *((int *)(data + sizeof(int) * 2));

    // Call the function-under-test
    int result = nc_inq_dimids(ncid, &ndims, dimids, include_parents);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result != 0) {
        printf("Function returned non-zero: %d\n", result);
    }

    return 0;
}