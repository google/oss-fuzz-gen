#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Assuming the function is declared in a header file, include it
// #include "netcdf.h" // Uncomment if the function is declared in netcdf.h

// Mocking the function-under-test for demonstration purposes
int nc_inq_dimlen_416(int ncid, int dimid, size_t *lenp) {
    // Mock behavior: just set lenp to a fixed value
    if (lenp != NULL) {
        *lenp = 42; // Example value
        return 0;   // Success
    }
    return -1; // Failure
}

int LLVMFuzzerTestOneInput_416(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2) {
        return 0; // Not enough data to extract two integers
    }

    int ncid = *((int *)data); // Extract the first integer
    int dimid = *((int *)(data + sizeof(int))); // Extract the second integer
    size_t len;

    // Call the function-under-test
    int result = nc_inq_dimlen_416(ncid, dimid, &len);

    // Optional: Print the result for debugging purposes
    printf("nc_inq_dimlen_416(%d, %d, &len) = %d, len = %zu\n", ncid, dimid, result, len);

    return 0;
}