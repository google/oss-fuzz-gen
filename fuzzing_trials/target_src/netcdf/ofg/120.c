#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_120(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract the required parameters
    if (size < sizeof(int) * 2 + sizeof(int) + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));
    int storage;
    size_t chunksize;

    // Call the function-under-test
    int result = nc_inq_var_chunking(ncid, varid, &storage, &chunksize);

    // Use the result, storage, and chunksize in some way to avoid unused variable warnings
    (void)result;
    (void)storage;
    (void)chunksize;

    return 0;
}