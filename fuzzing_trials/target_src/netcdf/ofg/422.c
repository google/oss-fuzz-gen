#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include "/src/netcdf-c/include/netcdf.h"

int LLVMFuzzerTestOneInput_422(const uint8_t *data, size_t size) {
    // Ensure that the input data is not null and has a size
    if (data == NULL || size == 0) {
        // Invalid input, return early
        return 0;
    }

    // Allocate a buffer to copy the input data
    void *data_copy = malloc(size);
    if (data_copy == NULL) {
        // Memory allocation failed, return early
        return 0;
    }

    // Copy the input data to the new buffer
    memcpy(data_copy, data, size);

    // Initialize the NetCDF library
    int init_result = nc_initialize();
    if (init_result != NC_NOERR) {
        // Initialization failed, free the allocated buffer and return an error code
        free(data_copy);
        return 0;
    }

    // Create a new NetCDF file in memory using the copied data
    int ncid;
    int retval = nc_create_mem("fuzz_test.nc", NC_CLOBBER, size, data_copy, &ncid);
    if (retval != NC_NOERR) {
        // File creation failed, free the allocated buffer and return early
        free(data_copy);
        return 0;
    }

    // Perform some operations on the NetCDF file
    // For demonstration, we'll just close the file
    retval = nc_close(ncid);
    if (retval != NC_NOERR) {
        // File closing failed, free the allocated buffer and return early
        free(data_copy);
        return 0;
    }

    // Free the allocated buffer
    free(data_copy);

    // Return 0 to indicate the fuzzer can continue
    return 0;
}