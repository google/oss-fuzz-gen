#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Assume this is the function we need to fuzz
int nc_get_vara_short(int ncid, int varid, const size_t *start, const size_t *count, short *data);

int LLVMFuzzerTestOneInput_351(const uint8_t *data, size_t size) {
    int ncid = 1; // Example value for ncid
    int varid = 1; // Example value for varid

    // Ensure the size is enough for at least one element for start and count arrays
    if (size < 2 * sizeof(size_t) + sizeof(short)) {
        return 0;
    }

    // Initialize start and count arrays
    size_t start[1];
    size_t count[1];

    // Extract values from the input data
    start[0] = *(const size_t *)data;
    count[0] = *(const size_t *)(data + sizeof(size_t));

    // Allocate memory for the data array
    short *data_array = (short *)malloc(count[0] * sizeof(short));
    if (data_array == NULL) {
        return 0;
    }

    // Call the function-under-test
    int result = nc_get_vara_short(ncid, varid, start, count, data_array);

    // Free the allocated memory
    free(data_array);

    return 0;
}