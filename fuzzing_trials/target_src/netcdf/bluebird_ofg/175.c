#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_175(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the fuzzing
    if (size < 2 * sizeof(size_t) + 2 * sizeof(int)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    size_t start[1];
    size_t count[1];

    start[0] = *((size_t *)(data + 2 * sizeof(int)));
    count[0] = *((size_t *)(data + 2 * sizeof(int) + sizeof(size_t)));

    // Calculate the remaining size for strings
    size_t remaining_size = size - 2 * sizeof(int) - 2 * sizeof(size_t);
    size_t num_strings = remaining_size / sizeof(char *);

    // Allocate memory for strings
    const char **string_data = (const char **)malloc(num_strings * sizeof(char *));
    if (string_data == NULL) {
        return 0;
    }

    // Initialize string data
    for (size_t i = 0; i < num_strings; i++) {
        string_data[i] = (const char *)(data + 2 * sizeof(int) + 2 * sizeof(size_t) + i * sizeof(char *));
    }

    // Call the function-under-test
    nc_put_vara_string(ncid, varid, start, count, string_data);

    // Free allocated memory
    free(string_data);

    return 0;
}