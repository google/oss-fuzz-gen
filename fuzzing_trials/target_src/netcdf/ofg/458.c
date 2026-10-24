#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_458(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid = 1; // Example non-zero integer for ncid
    int varid = 1; // Example non-zero integer for varid

    // Ensure size is sufficient to extract a valid index and value
    if (size < sizeof(size_t) + sizeof(unsigned char)) {
        return 0;
    }

    // Extract index from data
    size_t index;
    memcpy(&index, data, sizeof(size_t));

    // Extract value from data
    const unsigned char *value = data + sizeof(size_t);

    // Call the function-under-test
    nc_put_var1_ubyte(ncid, varid, &index, value);

    return 0;
}