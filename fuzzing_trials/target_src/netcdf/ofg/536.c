#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Mock function signature for nc_get_att
int nc_get_att(int ncid, int varid, const char *name, void *value);

// Fuzzing harness
int LLVMFuzzerTestOneInput_536(const uint8_t *data, size_t size) {
    // Ensure there's enough data to extract meaningful inputs
    if (size < 4) {
        return 0;
    }

    // Extract integers from data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Extract a string from data
    size_t name_len = (size > 4) ? size - 4 : 1;
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 2, name_len);
    name[name_len] = '\0';

    // Allocate a buffer for the value
    void *value = malloc(256);  // Arbitrary size for the value buffer
    if (value == NULL) {
        free(name);
        return 0;
    }

    // Call the function-under-test
    nc_get_att(ncid, varid, name, value);

    // Clean up
    free(name);
    free(value);

    return 0;
}