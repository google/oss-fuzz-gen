#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Function prototype for the function-under-test
int nc_get_vara_ulonglong(int ncid, int varid, const size_t *start, const size_t *count, unsigned long long *value);

int LLVMFuzzerTestOneInput_149(const uint8_t *data, size_t size) {
    // Ensure we have enough data to initialize parameters
    if (size < 5 * sizeof(size_t) + sizeof(unsigned long long)) {
        return 0;
    }

    // Initialize parameters
    int ncid = (int)data[0];
    int varid = (int)data[1];

    size_t start[2];
    size_t count[2];
    unsigned long long value;

    // Extract values from the data
    start[0] = (size_t)data[2];
    start[1] = (size_t)data[3];
    count[0] = (size_t)data[4];
    count[1] = (size_t)data[5];
    value = (unsigned long long)data[6];

    // Call the function-under-test
    nc_get_vara_ulonglong(ncid, varid, start, count, &value);

    return 0;
}