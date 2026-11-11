#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assume the header file for nc_get_att_short_3 is included
// #include <netcdf.h> // Uncomment this if the function is part of the NetCDF library

// Dummy implementation of nc_get_att_short_3 for illustration purposes
int nc_get_att_short_3(int ncid, int varid, const char *name, short *value) {
    // Simulate some processing
    if (ncid < 0 || varid < 0 || name == NULL || value == NULL) {
        return -1; // Error
    }
    // Assume the function writes a short value to the provided pointer
    *value = 42; // Dummy value
    return 0; // Success
}

int LLVMFuzzerTestOneInput_3(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0; // Not enough data to proceed
    }

    int ncid = data[0]; // Use the first byte as ncid
    int varid = data[1]; // Use the second byte as varid

    // Ensure there's enough data for a null-terminated string
    size_t name_len = size - 2;
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(name, data + 2, name_len);
    name[name_len] = '\0'; // Null-terminate the string

    // Ensure the name is not empty
    if (name_len == 0 || name[0] == '\0') {
        free(name);
        return 0; // Do not proceed with an empty name
    }

    short value;
    nc_get_att_short_3(ncid, varid, name, &value);

    free(name);
    return 0;
}