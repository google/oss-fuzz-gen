#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_260(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract required integers
    if (size < sizeof(int) * 3) {
        return 0;
    }

    // Extract integers from the input data
    int ncid = *((int *)data);
    int ntypes;
    int *typeids = (int *)(data + sizeof(int));

    // Call the function-under-test
    int result = nc_inq_typeids(ncid, &ntypes, typeids);

    // Use the result in some way to prevent compiler optimizations from removing the call
    if (result == NC_NOERR) {
        // Do something with ntypes and typeids if needed
    }

    return 0;
}