#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

// Assume the function signature is part of a library that is already linked
extern int nc_put_var_uint(int ncid, int varid, const unsigned int *op);

int LLVMFuzzerTestOneInput_213(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for our needs
    if (size < sizeof(unsigned int) + 2) {
        return 0;
    }

    // Initialize parameters for nc_put_var_uint_213
    int ncid = (int)data[0]; // Using first byte for ncid
    int varid = (int)data[1]; // Using second byte for varid

    // Allocate memory for the unsigned int array
    unsigned int *op = (unsigned int *)malloc(sizeof(unsigned int));
    if (op == NULL) {
        return 0;
    }

    // Initialize the unsigned int from the input data
    *op = *(unsigned int *)(data + 2);

    // Call the function-under-test
    nc_put_var_uint(ncid, varid, op);

    // Free allocated memory
    free(op);

    return 0;
}