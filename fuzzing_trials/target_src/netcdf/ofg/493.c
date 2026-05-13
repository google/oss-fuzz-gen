#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Function prototype for the function-under-test
int nc_get_var1_schar(int ncid, int varid, const size_t *indexp, signed char *valuep);

int LLVMFuzzerTestOneInput_493(const uint8_t *data, size_t size) {
    // Declare and initialize variables to pass to the function-under-test
    int ncid = 1; // Example value, should be a valid netCDF ID
    int varid = 1; // Example value, should be a valid variable ID

    // Ensure size is large enough to provide meaningful input
    if (size < sizeof(size_t) + sizeof(signed char)) {
        return 0;
    }

    // Use the first part of the data as the index
    size_t index = *((const size_t *)data);

    // Use the next part of the data as the signed char value
    signed char value = *((const signed char *)(data + sizeof(size_t)));

    // Call the function-under-test
    nc_get_var1_schar(ncid, varid, &index, &value);

    return 0;
}