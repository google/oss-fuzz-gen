#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Assuming the function is declared in a header file
// #include "netcdf.h"

// Mocking the function as we don't have the actual implementation
int nc_get_var1_longlong_333(int ncid, int varid, const size_t *indexp, long long *ip) {
    // Mock behavior for demonstration purposes
    if (ncid < 0 || varid < 0 || indexp == NULL || ip == NULL) {
        return -1; // Simulate an error
    }
    *ip = 123456789LL; // Assign some value
    return 0; // Success
}

int LLVMFuzzerTestOneInput_333(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) + 2) {
        return 0; // Not enough data to form a valid input
    }

    int ncid = (int)data[0]; // Using the first byte as ncid
    int varid = (int)data[1]; // Using the second byte as varid

    // Use the remaining data as the size_t index
    const size_t *indexp = (const size_t *)(data + 2);

    long long ip;
    
    // Call the function-under-test
    int result = nc_get_var1_longlong_333(ncid, varid, indexp, &ip);

    // For debugging purposes, print the result and ip value
    printf("Result: %d, Value: %lld\n", result, ip);

    return 0;
}