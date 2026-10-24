#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

// Assume this is the function-under-test
int nc_get_vara_long(int ncid, int varid, const size_t *start, const size_t *count, long *data);

int LLVMFuzzerTestOneInput_440(const uint8_t *data, size_t size) {
    if (size < 2 * sizeof(size_t) + sizeof(int) * 2) {
        return 0;  // Not enough data to proceed
    }

    int ncid = (int)data[0];
    int varid = (int)data[1];

    const size_t *start = (const size_t *)(data + 2 * sizeof(int));
    const size_t *count = (const size_t *)(data + 2 * sizeof(int) + sizeof(size_t));

    size_t num_elements = 1;
    for (size_t i = 0; i < sizeof(size_t) / sizeof(size_t); i++) {
        num_elements *= count[i];
    }

    long *data_array = (long *)malloc(num_elements * sizeof(long));
    if (data_array == NULL) {
        return 0;  // Memory allocation failed
    }

    // Call the function-under-test
    nc_get_vara_long(ncid, varid, start, count, data_array);

    free(data_array);
    return 0;
}