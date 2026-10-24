#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h> // Include string.h for compatibility

// Mock function definition for nc_def_var_chunking_412
int nc_def_var_chunking_412(int ncid, int varid, int storage, const size_t *chunksizes) {
    // This is a placeholder for the actual implementation.
    // In a real scenario, the actual function from the library would be used.
    return 0; // Return success for the sake of this example.
}

int LLVMFuzzerTestOneInput_412(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract parameters
    if (size < sizeof(int) * 3 + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    int storage = *((int *)(data + 2 * sizeof(int)));
    const size_t *chunksizes = (const size_t *)(data + 3 * sizeof(int));

    // Call the function-under-test
    nc_def_var_chunking_412(ncid, varid, storage, chunksizes);

    return 0;
}