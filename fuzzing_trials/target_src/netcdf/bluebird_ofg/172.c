#include <stdint.h>
#include <stddef.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_172(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid = 1; // Example non-zero value for the netCDF ID
    int varid = 1; // Example non-zero value for the variable ID

    // Ensure there is enough data to extract the start and count arrays
    if (size < 2 * sizeof(size_t)) {
        return 0;
    }

    // Extract start and count arrays from the input data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));

    // Ensure there is enough data left for the text data
    if (size < 2 * sizeof(size_t) + 1) {
        return 0;
    }

    // Extract the text data from the input data
    const char *text = (const char *)(data + 2 * sizeof(size_t));

    // Call the function under test
    nc_put_vara_text(ncid, varid, start, count, text);

    return 0;
}