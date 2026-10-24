#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

// Assuming the function is part of a library that needs to be included
// You should replace this with the actual header file where nc_get_vara_short_352 is declared
#include "netcdf.h"

// Mock implementation of nc_get_vara_short_352 for demonstration purposes
int nc_get_vara_short_352(int ncid, int varid, const size_t *start, const size_t *count, short *value) {
    // Simulated function logic
    if (start == NULL || count == NULL || value == NULL) {
        return -1; // Return error if any input is NULL
    }
    // Simulate some operation on the inputs
    *value = (short)(ncid + varid + start[0] + start[1] + count[0] + count[1]);
    return 0; // Return success
}

int LLVMFuzzerTestOneInput_352(const uint8_t *data, size_t size) {
    if (size < 4 * sizeof(size_t) + sizeof(short)) {
        return 0; // Ensure there's enough data for the inputs
    }

    int ncid = (int)data[0];
    int varid = (int)data[1];

    size_t start[2];
    size_t count[2];
    short value;

    // Initialize start and count arrays with more meaningful values
    start[0] = (size_t)data[2] % 10; // Limit the range to simulate realistic values
    start[1] = (size_t)data[3] % 10;
    count[0] = (size_t)data[4] % 10;
    count[1] = (size_t)data[5] % 10;

    // Initialize value
    value = (short)data[6];

    // Call the function under test
    int result = nc_get_vara_short_352(ncid, varid, start, count, &value);

    // Check the result to ensure the function is being exercised
    if (result != 0) {
        fprintf(stderr, "nc_get_vara_short_352 returned an error: %d\n", result);
    }

    return 0;
}