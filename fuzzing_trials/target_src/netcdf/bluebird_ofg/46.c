#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

extern int nc_get_vara(int ncid, int varid, const size_t *start, const size_t *count, void *data);

int LLVMFuzzerTestOneInput_46(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 1;  // Example non-zero value
    int varid = 1; // Example non-zero value

    // Ensure that size is sufficient to create start and count arrays
    if (size < 2 * sizeof(size_t)) {
        return 0;
    }

    // Create start and count arrays with non-zero values
    size_t start[1];
    size_t count[1];

    start[0] = (size_t)data[0] + 1; // Ensure non-zero
    count[0] = (size_t)data[1] + 1; // Ensure non-zero

    // Allocate memory for data buffer
    void *data_buffer = malloc(count[0] * sizeof(int));
    if (data_buffer == NULL) {
        return 0;
    }

    // Call the function-under-test
    nc_get_vara(ncid, varid, start, count, data_buffer);

    // Free allocated memory
    free(data_buffer);

    return 0;
}