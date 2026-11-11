#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_567(const uint8_t *data, size_t size) {
    // Ensure size is sufficient to extract an integer
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract an integer from the data for the ncid parameter
    int ncid = *(const int *)data;

    // Allocate memory for the natts parameter
    int natts = 0;

    // Call the function-under-test
    int result = nc_inq_natts(ncid, &natts);

    // Optionally, you can print or log the result and natts for debugging
    // printf("Result: %d, Number of attributes: %d\n", result, natts);

    return 0;
}