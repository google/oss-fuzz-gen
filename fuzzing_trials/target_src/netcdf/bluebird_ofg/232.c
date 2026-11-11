#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_232(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 0; // NetCDF file ID, assuming a valid ID for testing
    int varid = 0; // NetCDF variable ID, assuming a valid ID for testing
    size_t index[1]; // Index array for the variable
    unsigned char value;

    // Ensure the input size is sufficient to extract necessary values
    if (size < sizeof(size_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Extract index and value from the input data
    index[0] = *((size_t *)data);
    value = *((unsigned char *)(data + sizeof(size_t)));

    // Call the function-under-test
    nc_put_var1_ubyte(ncid, varid, index, &value);

    return 0;
}