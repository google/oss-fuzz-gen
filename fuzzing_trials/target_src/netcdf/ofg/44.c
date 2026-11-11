#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Function signature for the function-under-test
int nc_get_vara_ushort(int ncid, int varid, const size_t *start, const size_t *count, unsigned short *value);

int LLVMFuzzerTestOneInput_44(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function-under-test
    int ncid = 1; // Example non-zero value
    int varid = 1; // Example non-zero value

    // Ensure that the size is sufficient to extract start and count arrays
    if (size < 4 * sizeof(size_t)) {
        return 0;
    }

    // Extract start and count arrays from the input data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + 2 * sizeof(size_t));

    // Allocate memory for the value array based on count
    size_t total_count = count[0] * count[1]; // Assuming 2D array for simplicity
    unsigned short *value = (unsigned short *)malloc(total_count * sizeof(unsigned short));
    if (value == NULL) {
        return 0;
    }

    // Call the function-under-test
    nc_get_vara_ushort(ncid, varid, start, count, value);

    // Free the allocated memory
    free(value);

    return 0;
}