#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_126(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract three integers
    if (size < 3 * sizeof(int)) {
        return 0;
    }

    // Extract three integers from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    int fletcher32 = 0; // Initialize the third parameter

    // Call the function-under-test
    int result = nc_inq_var_fletcher32(ncid, varid, &fletcher32);

    // Optionally print the result for debugging purposes
    printf("Result: %d, Fletcher32: %d\n", result, fletcher32);

    return 0;
}