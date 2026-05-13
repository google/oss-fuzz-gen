#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assume the function is defined in some library we are linking against
extern int nc_get_vara_ushort(int ncid, int varid, const size_t *start, const size_t *count, unsigned short *value);

int LLVMFuzzerTestOneInput_45(const uint8_t *data, size_t size) {
    // Declare and initialize the parameters for nc_get_vara_ushort
    int ncid = 1;  // Example non-zero value
    int varid = 1; // Example non-zero value

    // Ensure there is enough data to read start and count arrays
    if (size < 2 * sizeof(size_t)) {
        return 0;
    }

    // Initialize start and count arrays
    size_t start[1];
    size_t count[1];

    // Copy data into start and count arrays
    memcpy(start, data, sizeof(size_t));
    memcpy(count, data + sizeof(size_t), sizeof(size_t));

    // Allocate memory for the value array based on count
    unsigned short *value = (unsigned short *)malloc(*count * sizeof(unsigned short));
    if (value == NULL) {
        return 0;
    }

    // Call the function-under-test
    nc_get_vara_ushort(ncid, varid, start, count, value);

    // Clean up
    free(value);

    return 0;
}