#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_515(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid;
    int nvars;

    // Check if the size is sufficient to extract an integer for ncid
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract ncid from the data
    ncid = *(const int *)data;

    // Call the function-under-test
    int result = nc_inq_nvars(ncid, &nvars);

    // Print the result and number of variables for debugging purposes
    printf("Result: %d, Number of Variables: %d\n", result, nvars);

    return 0;
}