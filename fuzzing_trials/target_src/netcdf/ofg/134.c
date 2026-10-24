#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Assuming the function signature is defined in a header file
// #include "netcdf.h" // Uncomment this if the function is defined in a header

// Mock implementation of the function-under-test
// Remove this mock implementation when linking against the actual library
int nc_put_vars_long_134(int ncid, int varid, const size_t *start, const size_t *count, const ptrdiff_t *stride, const long *values) {
    // Mock behavior: simply print the inputs for demonstration purposes
    printf("ncid: %d, varid: %d\n", ncid, varid);
    printf("start: %zu, count: %zu, stride: %td, values: %ld\n", *start, *count, *stride, *values);
    return 0; // Mock return value
}

int LLVMFuzzerTestOneInput_134(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(long)) {
        return 0; // Not enough data to fill all parameters
    }

    int ncid = 1;  // Example non-null value
    int varid = 1; // Example non-null value

    // Assigning values from `data` to parameters
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);
    const long *values = (const long *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Call the function-under-test
    nc_put_vars_long_134(ncid, varid, start, count, stride, values);

    return 0;
}