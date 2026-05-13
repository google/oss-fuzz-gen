#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h" // Include the relevant header for nc_inq_var_chunking

int LLVMFuzzerTestOneInput_77(const uint8_t *data, size_t size) {
    // Ensure that the input data is large enough to extract necessary integers
    if (size < sizeof(int) * 2 + sizeof(int) + sizeof(size_t)) {
        return 0;
    }

    // Extract integers from the data
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + sizeof(int));
    int storage;
    size_t chunksize;

    // Call the function-under-test
    int result = nc_inq_var_chunking(ncid, varid, &storage, &chunksize);

    // Use the result, storage, and chunksize for further logic if necessary
    // For fuzzing purposes, we are mainly interested in calling the function

    return 0;
}