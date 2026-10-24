#include <stdint.h>
#include <stddef.h>
#include <string.h>  // Include this for memcpy
#include <netcdf.h>

int LLVMFuzzerTestOneInput_228(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function-under-test
    int ncid = 1; // Example netCDF ID, should be a valid ID in a real scenario
    int varid = 1; // Example variable ID, should be a valid ID in a real scenario

    // Ensure the size is sufficient for the index and value
    if (size < sizeof(size_t) + sizeof(float)) {
        return 0;
    }

    // Extract a size_t index from the data
    size_t index;
    memcpy(&index, data, sizeof(size_t));

    // Extract a float value from the data
    float value;
    memcpy(&value, data + sizeof(size_t), sizeof(float));

    // Call the function-under-test
    nc_put_var1_float(ncid, varid, &index, &value);

    return 0;
}