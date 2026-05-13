#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Assume the function is part of a library that we have access to.
int nc_put_var1_short(int ncid, int varid, const size_t *indexp, const short *valuep);

int LLVMFuzzerTestOneInput_386(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 1;  // Example non-zero value for ncid
    int varid = 1; // Example non-zero value for varid

    // Ensure there is enough data for index and value
    if (size < sizeof(size_t) + sizeof(short)) {
        return 0;
    }

    // Extract index and value from the fuzzing data
    const size_t *indexp = (const size_t *)data;
    const short *valuep = (const short *)(data + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1_short(ncid, varid, indexp, valuep);

    return 0;
}