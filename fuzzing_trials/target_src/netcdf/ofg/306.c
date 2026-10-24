#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_306(const uint8_t *data, size_t size) {
    // Declare and initialize variables for nc_put_var1 parameters
    int ncid = 0; // NetCDF file ID, assuming 0 for testing
    int varid = 0; // Variable ID, assuming 0 for testing

    // Ensure size is sufficient to create a valid index
    if (size < sizeof(size_t)) {
        return 0;
    }

    // Create a valid index from the input data
    size_t index = 0;
    if (size >= sizeof(size_t)) {
        index = *((const size_t *)data);
    }

    // Ensure size is sufficient to create a valid value
    const void *value = (const void *)(data + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1(ncid, varid, &index, value);

    return 0;
}