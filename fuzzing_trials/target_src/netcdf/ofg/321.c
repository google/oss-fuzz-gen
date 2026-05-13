#include <stdint.h>
#include <stddef.h>
#include <stdio.h>

// Assuming the function is part of a library, include the necessary header
// #include <netcdf.h> // Uncomment this if the function is part of the NetCDF library

// Mock function definition for illustration purposes
// Remove this when using the actual library function
int nc_put_var1_ulonglong_321(int ncid, int varid, const size_t *indexp, const unsigned long long *value) {
    // Mock implementation
    return 0;
}

int LLVMFuzzerTestOneInput_321(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) + sizeof(unsigned long long)) {
        return 0; // Not enough data to proceed
    }

    // Extracting the parameters from the input data
    int ncid = (int)data[0]; // Using the first byte for ncid
    int varid = (int)data[1]; // Using the second byte for varid

    // Using the next bytes for indexp
    const size_t *indexp = (const size_t *)(data + 2);

    // Using the remaining bytes for value
    const unsigned long long *value = (const unsigned long long *)(data + 2 + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1_ulonglong_321(ncid, varid, indexp, value);

    return 0;
}