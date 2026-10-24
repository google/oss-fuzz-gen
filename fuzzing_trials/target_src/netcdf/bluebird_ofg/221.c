#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Mock function signature for demonstration purposes
int nc_get_var1_float(int ncid, int varid, const size_t *indexp, float *fp);

int LLVMFuzzerTestOneInput_221(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(float)) {
        return 0; // Not enough data to populate all parameters
    }

    int ncid = *(int *)data;
    int varid = *(int *)(data + sizeof(int));
    size_t index = *(size_t *)(data + 2 * sizeof(int));
    float value = *(float *)(data + 2 * sizeof(int) + sizeof(size_t));

    // Call the function-under-test
    int result = nc_get_var1_float(ncid, varid, &index, &value);

    // Use the result to avoid compiler optimizations removing the call
    (void)result;

    return 0;
}