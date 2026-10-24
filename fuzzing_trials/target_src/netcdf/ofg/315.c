#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_315(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 1;  // Example netCDF file ID, should be a valid ID in a real scenario
    int varid = 1; // Example variable ID, should be a valid ID in a real scenario

    // Ensure there is enough data to form at least one float
    if (size < sizeof(float)) {
        return 0;
    }

    // Allocate memory for the float array
    size_t num_floats = size / sizeof(float);
    float *float_array = (float *)malloc(num_floats * sizeof(float));
    if (float_array == NULL) {
        return 0;
    }

    // Copy data into the float array
    for (size_t i = 0; i < num_floats; i++) {
        float_array[i] = ((float *)data)[i];
    }

    // Call the function-under-test
    nc_put_var_float(ncid, varid, float_array);

    // Free allocated memory
    free(float_array);

    return 0;
}