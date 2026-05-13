#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Function prototype for the function-under-test
int nc_put_var_int(int ncid, int varid, const int *op);

int LLVMFuzzerTestOneInput_199(const uint8_t *data, size_t size) {
    // Ensure that size is sufficient to extract three integers
    if (size < sizeof(int) * 3) {
        return 0;
    }

    // Extract integers from the input data
    int ncid = *((const int *)data);
    int varid = *((const int *)(data + sizeof(int)));
    const int *op = (const int *)(data + 2 * sizeof(int));

    // Ensure op is not null and points to valid data
    if (op == NULL) {
        return 0;
    }

    // Call the function-under-test
    nc_put_var_int(ncid, varid, op);

    return 0;
}