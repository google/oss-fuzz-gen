#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_507(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for the function-under-test
    int ncid = 0; // Assuming a valid netCDF file ID for testing
    int varid = 0; // Assuming a valid variable ID for testing

    // Ensure that the size is large enough to extract at least one size_t and one unsigned char
    if (size < sizeof(size_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Extract a size_t index from the input data
    size_t index;
    memcpy(&index, data, sizeof(size_t));

    // Extract an unsigned char value from the input data
    const unsigned char *value = data + sizeof(size_t);

    // Call the function-under-test
    nc_put_var1_uchar(ncid, varid, &index, value);

    return 0;
}