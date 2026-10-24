#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h> // Added for completeness, though not directly needed for this error

// Function-under-test
int nc_get_var1_string(int ncid, int varid, const size_t *indexp, char **strp);

int LLVMFuzzerTestOneInput_193(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient for our needs
    if (size < sizeof(size_t) + 2 * sizeof(int)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = (int)data[0];
    int varid = (int)data[1];
    size_t index = (size_t)data[2];

    // Allocate memory for char* strp
    char *strp = (char *)malloc(256); // Allocate a fixed size for the string
    if (strp == NULL) {
        return 0;
    }

    // Initialize strp with some data
    memset(strp, 'A', 255);
    strp[255] = '\0';

    // Call the function-under-test
    nc_get_var1_string(ncid, varid, &index, &strp);

    // Free allocated memory
    free(strp);

    return 0;
}