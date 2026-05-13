#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assume the function is declared in an external library
extern int nc_get_att_long(int ncid, int varid, const char *name, long *values);

int LLVMFuzzerTestOneInput_67(const uint8_t *data, size_t size) {
    // Ensure that the size is large enough to extract necessary parameters
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    // Allocate memory for the name and ensure it's null-terminated
    size_t name_len = size - sizeof(int) * 2;
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + sizeof(int) * 2, name_len);
    name[name_len] = '\0';

    // Allocate memory for the output values
    long values[10]; // Arbitrary size for demonstration

    // Call the function-under-test
    nc_get_att_long(ncid, varid, name, values);

    // Clean up
    free(name);

    return 0;
}