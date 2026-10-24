#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Assuming the function is part of a library that provides this signature
int nc_put_var(int ncid, int varid, const void *data);

int LLVMFuzzerTestOneInput_203(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for the parameters
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract the first integer for ncid
    int ncid = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the second integer for varid
    int varid = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // The remaining data is used as the void* data parameter
    const void *var_data = (const void *)data;

    // Call the function-under-test
    nc_put_var(ncid, varid, var_data);

    return 0;
}