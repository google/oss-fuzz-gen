#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_21(const uint8_t *data, size_t size) {
    // Define and initialize parameters for nc_put_vara
    int ncid = 1; // Example non-zero file ID
    int varid = 1; // Example non-zero variable ID

    // Ensure we have enough data to create start and count arrays
    if (size < 2 * sizeof(size_t)) {
        return 0;
    }

    // Create start and count arrays from the input data
    size_t start[1];
    size_t count[1];
    memcpy(start, data, sizeof(size_t));
    memcpy(count, data + sizeof(size_t), sizeof(size_t));

    // Ensure we have enough data for the value array
    if (size < 2 * sizeof(size_t) + sizeof(int)) {
        return 0;
    }

    // Create a value array from the input data
    const void *value = (const void *)(data + 2 * sizeof(size_t));

    // Call the function-under-test
    nc_put_vara(ncid, varid, start, count, value);

    return 0;
}