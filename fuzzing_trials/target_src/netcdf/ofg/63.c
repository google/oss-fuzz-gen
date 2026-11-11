#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Function signature provided
int nc_get_var1_float(int ncid, int varid, const size_t *indexp, float *fp);

int LLVMFuzzerTestOneInput_63(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid = 1;  // Example value, should be non-zero
    int varid = 1; // Example value, should be non-zero
    size_t index = 0; // Example index, assuming a single index for simplicity
    float value = 0.0f; // Placeholder for the float value to be retrieved

    // Ensure the data size is sufficient for the index
    if (size < sizeof(size_t)) {
        return 0;
    }

    // Use the provided data to set the index value
    index = *((size_t *)data);

    // Call the function-under-test
    nc_get_var1_float(ncid, varid, &index, &value);

    return 0;
}