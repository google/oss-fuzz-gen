#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

// Mock function signature for nc_put_var_uint_212
int nc_put_var_uint_212(int ncid, int varid, const unsigned int *op) {
    // Mock implementation for demonstration purposes
    // Assume this function returns non-zero on error
    return (op == NULL) ? -1 : 0;
}

int LLVMFuzzerTestOneInput_212(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for two integers and at least one unsigned int
    if (size < sizeof(int) * 2 + sizeof(unsigned int)) {
        return 0;
    }

    // Extract ncid and varid from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    // Calculate the number of unsigned ints in the remaining data
    size_t num_uints = (size - sizeof(int) * 2) / sizeof(unsigned int);

    // Allocate memory for the unsigned int array
    unsigned int *op = (unsigned int *)malloc(num_uints * sizeof(unsigned int));
    if (op == NULL) {
        return 0;
    }

    // Copy the unsigned int values from the input data
    for (size_t i = 0; i < num_uints; i++) {
        op[i] = *((unsigned int *)(data + sizeof(int) * 2 + i * sizeof(unsigned int)));
    }

    // Ensure that the function is called with non-null input
    if (num_uints > 0) {
        // Call the function-under-test
        int result = nc_put_var_uint_212(ncid, varid, op);

        // Check the result to ensure the function is behaving as expected
        if (result != 0) {
            fprintf(stderr, "nc_put_var_uint_212 returned an error: %d\n", result);
        }
    }

    // Free the allocated memory
    free(op);

    return 0;
}