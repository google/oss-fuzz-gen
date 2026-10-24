#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Mock function signature for illustration purposes
int nc_get_vara_string(int ncid, int varid, const size_t *start, const size_t *count, char **stringp);

int LLVMFuzzerTestOneInput_255(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our parameters
    if (size < sizeof(size_t) * 2 + sizeof(int) * 2) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));

    const size_t *start = (const size_t *)(data + 2 * sizeof(int));
    const size_t *count = (const size_t *)(data + 2 * sizeof(int) + sizeof(size_t));

    // Allocate memory for the string pointer
    char *stringp = (char *)malloc(256); // Allocate a buffer of 256 bytes
    if (stringp == NULL) {
        return 0;
    }

    // Initialize the allocated memory to avoid undefined behavior
    memset(stringp, 0, 256);

    // Call the function-under-test
    nc_get_vara_string(ncid, varid, start, count, &stringp);

    // Free the allocated memory
    free(stringp);

    return 0;
}