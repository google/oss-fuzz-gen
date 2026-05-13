#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_246(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid = 0;  // Assuming a valid non-negative integer for ncid
    int varid = 0; // Assuming a valid non-negative integer for varid

    // Ensure size is large enough to create start and count arrays
    if (size < 2 * sizeof(size_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Create and initialize start and count arrays
    size_t start[1];
    size_t count[1];
    start[0] = (size_t)data[0]; // Initialize with some value from data
    count[0] = (size_t)data[1]; // Initialize with some value from data

    // Ensure count is non-zero to avoid issues
    if (count[0] == 0) {
        count[0] = 1;
    }

    // Create and initialize the value array
    unsigned char *value = (unsigned char *)malloc(count[0] * sizeof(unsigned char));
    if (value == NULL) {
        return 0;
    }

    // Fill the value array with data
    memcpy(value, data + 2 * sizeof(size_t), count[0] * sizeof(unsigned char));

    // Call the function-under-test
    nc_put_vara_ubyte(ncid, varid, start, count, value);

    // Clean up
    free(value);

    return 0;
}