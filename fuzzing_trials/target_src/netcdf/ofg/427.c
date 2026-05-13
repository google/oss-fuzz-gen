#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assume the function is defined in an external library
extern int nc_get_att_float(int ncid, int varid, const char *name, float *value);

int LLVMFuzzerTestOneInput_427(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract meaningful inputs
    if (size < 8) {
        return 0;
    }

    // Extract integer values for ncid and varid
    int ncid = *(const int *)(data);
    int varid = *(const int *)(data + 4);

    // Extract a string for the name
    size_t name_length = size - 8; // Remaining data for the name
    char *name = (char *)malloc(name_length + 1);
    if (name == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(name, data + 8, name_length);
    name[name_length] = '\0'; // Null-terminate the string

    // Prepare a float buffer for the output
    float value;

    // Call the function-under-test
    nc_get_att_float(ncid, varid, name, &value);

    // Clean up
    free(name);

    return 0;
}