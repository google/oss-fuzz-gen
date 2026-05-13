#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_181(const uint8_t *data, size_t size) {
    // Ensure that the input size is large enough to extract necessary parameters
    if (size < sizeof(size_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Initialize parameters for nc_put_var1_uint
    int ncid = 0; // Example netCDF file ID, should be a valid ID in a real scenario
    int varid = 0; // Example variable ID, should be a valid ID in a real scenario

    // Extract a size_t index from the input data
    size_t index;
    memcpy(&index, data, sizeof(size_t));

    // Extract an unsigned int value from the input data
    unsigned int value;
    memcpy(&value, data + sizeof(size_t), sizeof(unsigned int));

    // Call the function-under-test
    nc_put_var1_uint(ncid, varid, &index, &value);

    return 0;
}