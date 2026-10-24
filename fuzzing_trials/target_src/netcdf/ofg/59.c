#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Ensure there's enough data for the parameters
    if (size < sizeof(size_t) + sizeof(long long)) {
        return 0;
    }

    // Initialize parameters for nc_put_var1_longlong
    int ncid = 0; // Example NetCDF file ID
    int varid = 0; // Example variable ID

    // Allocate and initialize the index parameter
    size_t *index = (size_t *)malloc(sizeof(size_t));
    if (index == NULL) {
        return 0;
    }
    *index = *(const size_t *)data; // Use data to initialize index

    // Allocate and initialize the value parameter
    const long long *value = (const long long *)(data + sizeof(size_t));

    // Call the function-under-test
    int result = nc_put_var1_longlong(ncid, varid, index, value);

    // Clean up allocated memory
    free(index);

    return 0;
}