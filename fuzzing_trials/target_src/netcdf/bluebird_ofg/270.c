#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

extern int nc__create_mp(const char *path, int mode, size_t size, int flags, size_t *out_size, int *out_flags);

int LLVMFuzzerTestOneInput_270(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract meaningful inputs
    if (size < sizeof(int) * 2 + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract inputs from the data
    // Ensure the path is null-terminated
    size_t path_len = strnlen((const char *)data, size);
    char *path = (char *)malloc(path_len + 1);
    if (!path) {
        return 0;
    }
    memcpy(path, data, path_len);
    path[path_len] = '\0';

    // Ensure there's enough data for mode, mp_size, and flags after the path
    if (size < path_len + sizeof(int) * 2 + sizeof(size_t)) {
        free(path);
        return 0;
    }

    // Extract mode, mp_size, and flags from the data after the path
    int mode = (int)data[path_len];
    size_t mp_size = (size_t)data[path_len + 1];
    int flags = (int)data[path_len + 2];

    // Allocate memory for out_size and out_flags
    size_t out_size;
    int out_flags;

    // Call the function-under-test
    nc__create_mp(path, mode, mp_size, flags, &out_size, &out_flags);

    // Free the allocated memory for path
    free(path);

    return 0;
}