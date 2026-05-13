#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assuming the function is declared in the relevant header file
// #include <netcdf.h>

// Mocking the function for demonstration purposes
int nc_get_att_double_69(int ncid, int varid, const char *name, double *value) {
    // Mock implementation
    if (ncid < 0 || varid < 0 || name == NULL || value == NULL) {
        return -1; // Error
    }
    *value = 42.0; // Dummy value
    return 0; // Success
}

int LLVMFuzzerTestOneInput_69(const uint8_t *data, size_t size) {
    if (size < 3) {
        return 0; // Not enough data to proceed
    }

    // Extracting values from the data
    int ncid = (int)data[0];
    int varid = (int)data[1];
    size_t name_len = size - 2;

    // Allocate memory for the name and ensure it is null-terminated
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0; // Allocation failed
    }
    memcpy(name, data + 2, name_len);
    name[name_len] = '\0';

    double value;
    
    // Call the function-under-test
    nc_get_att_double_69(ncid, varid, name, &value);

    // Clean up
    free(name);

    return 0;
}