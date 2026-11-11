#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Mock function to represent nc_inq_path_355
int nc_inq_path_355(int ncid, size_t *lenp, char *path) {
    // This is a placeholder for the actual implementation.
    // It should be replaced with the real function during actual fuzzing.
    return 0;
}

int LLVMFuzzerTestOneInput_355(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(size_t)) {
        return 0; // Not enough data to fill ncid and lenp
    }

    // Extract an integer from the data
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract a size_t from the data
    size_t len = *(const size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Allocate memory for the path and ensure it's null-terminated
    char *path = (char *)malloc(len + 1);
    if (path == NULL) {
        return 0; // Memory allocation failed
    }

    // Copy the remaining data into path
    size_t copy_size = size < len ? size : len;
    memcpy(path, data, copy_size);
    path[copy_size] = '\0'; // Null-terminate the path

    // Call the function under test
    nc_inq_path_355(ncid, &len, path);

    // Free allocated memory
    free(path);

    return 0;
}