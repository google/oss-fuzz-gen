#include <stdint.h>
#include <stddef.h>

// Assuming the function is part of a library that needs to be included
#include <netcdf.h>

// Function-under-test
int nc_put_var(int ncid, int varid, const void *op);

// Fuzzer entry point
int LLVMFuzzerTestOneInput_114(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid = 1; // Example non-zero file ID
    int varid = 1; // Example non-zero variable ID
    const void *op = (const void *)data; // Use the data as the input buffer

    // Call the function-under-test
    nc_put_var(ncid, varid, op);

    return 0;
}