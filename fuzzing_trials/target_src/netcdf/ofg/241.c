#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>  // Added for memcpy

// Assuming the function is declared in a header file named "netcdf.h"
#include "netcdf.h"

// Mock implementation of the function-under-test
// In a real scenario, this would be provided by the NetCDF library.
int nc_put_var_ulonglong_241(int ncid, int varid, const unsigned long long *op) {
    // Mock behavior
    if (op == NULL) {
        return -1; // Simulate error for NULL pointer
    }
    printf("ncid: %d, varid: %d, value: %llu\n", ncid, varid, *op);
    return 0; // Simulate success
}

int LLVMFuzzerTestOneInput_241(const uint8_t *data, size_t size) {
    if (size < sizeof(unsigned long long)) {
        return 0; // Not enough data to form a valid unsigned long long
    }

    // Initialize parameters for nc_put_var_ulonglong_241
    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value
    unsigned long long value;

    // Copy data into the unsigned long long value
    memcpy(&value, data, sizeof(unsigned long long));

    // Call the function-under-test
    nc_put_var_ulonglong_241(ncid, varid, &value);

    return 0;
}