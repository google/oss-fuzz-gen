#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_413(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract parameters
    if (size < sizeof(int) * 3 + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data); // First 4 bytes for ncid
    int varid = *((int *)(data + sizeof(int))); // Next 4 bytes for varid
    int storage = *((int *)(data + 2 * sizeof(int))); // Next 4 bytes for storage
    const size_t *chunksizesp = (const size_t *)(data + 3 * sizeof(int)); // Next sizeof(size_t) bytes for chunksizesp

    // Call the function-under-test
    int result = nc_def_var_chunking(ncid, varid, storage, chunksizesp);

    // Print the result (optional, for debugging purposes)
    printf("nc_def_var_chunking_413 returned: %d\n", result);

    return 0;
}