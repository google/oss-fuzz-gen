#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Assuming the function is declared in a header file
// #include "netcdf.h"

// Mock function definition for nc_inq_format_411
int nc_inq_format_411(int ncid, int *formatp) {
    // Mock implementation, replace with actual function call
    *formatp = 1; // Example format
    return 0; // Assume success
}

int LLVMFuzzerTestOneInput_411(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for our needs
    if (size < sizeof(int)) {
        return 0;
    }

    // Interpret the first part of data as an integer
    int ncid = *(const int *)data;

    // Declare and initialize the format variable
    int format = 0;

    // Call the function-under-test
    int result = nc_inq_format_411(ncid, &format);

    // Optionally, print the result and format for debugging purposes
    printf("Result: %d, Format: %d\n", result, format);

    return 0;
}