#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Function-under-test declaration
int nc_put_vara_uint(int ncid, int varid, const size_t *start, const size_t *count, const unsigned int *value);

int LLVMFuzzerTestOneInput_415(const uint8_t *data, size_t size) {
    // Ensure there's enough data to initialize parameters
    if (size < 2 * sizeof(int) + 4 * sizeof(size_t) + sizeof(unsigned int)) {
        return 0;
    }

    // Initialize parameters
    int ncid;
    int varid;
    memcpy(&ncid, data, sizeof(int));
    memcpy(&varid, data + sizeof(int), sizeof(int));

    // Initialize start and count arrays
    size_t start[2];
    size_t count[2];
    memcpy(start, data + 2 * sizeof(int), 2 * sizeof(size_t));
    memcpy(count, data + 2 * sizeof(int) + 2 * sizeof(size_t), 2 * sizeof(size_t));

    // Initialize value array
    unsigned int value[1];
    memcpy(value, data + 2 * sizeof(int) + 4 * sizeof(size_t), sizeof(unsigned int));

    // Call the function-under-test
    nc_put_vara_uint(ncid, varid, start, count, value);

    return 0;
}