#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

// Assuming the function is declared in a header file
// #include "netcdf.h" 

// Mock function definition for illustration purposes
int nc_get_att_schar_428(int ncid, int varid, const char *name, signed char *value) {
    // Mock implementation
    return 0;
}

int LLVMFuzzerTestOneInput_428(const uint8_t *data, size_t size) {
    if (size < 4) { // Ensure there is enough data for ncid, varid, and at least two chars for name
        return 0;
    }

    // Use the first two bytes for ncid and varid
    int ncid = data[0];
    int varid = data[1];

    // Allocate memory for the name and ensure it's null-terminated
    size_t name_len = size - 3;
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 2, name_len);
    name[name_len] = '\0';

    // Ensure the name is not empty by appending a character if necessary
    if (name_len == 0 || name[0] == '\0') {
        name[0] = 'a'; // Assign a default character
        name[1] = '\0';
    }

    // Allocate memory for the signed char value
    signed char value = 0;

    // Call the function-under-test
    nc_get_att_schar_428(ncid, varid, name, &value);

    // Free allocated memory
    free(name);

    return 0;
}