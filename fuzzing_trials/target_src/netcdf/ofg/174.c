#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_174(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < 4 * sizeof(size_t) + sizeof(signed char)) {
        return 0;
    }

    // Initialize parameters
    int ncid = 1;  // Example non-zero value
    int varid = 1; // Example non-zero value

    // Use the data to initialize start and count arrays
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + 2 * sizeof(size_t));

    // Use the remaining data for the signed char values
    const signed char *values = (const signed char *)(data + 4 * sizeof(size_t));

    // Call the function-under-test
    nc_put_vara_schar(ncid, varid, start, count, values);

    return 0;
}