#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_121(const uint8_t *data, size_t size) {
    int ncid;
    int nvars;

    // Ensure we have enough data to extract an integer for ncid
    if (size < sizeof(int)) {
        return 0;
    }

    // Extract ncid from the input data
    ncid = *(int *)data;

    // Call the function-under-test
    int result = nc_inq_nvars(ncid, &nvars);

    // Optionally, you can print the result or nvars for debugging purposes
    printf("Result: %d, Number of variables: %d\n", result, nvars);

    return 0;
}