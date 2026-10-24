#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h> // Include the NetCDF header for the nc_get_att_string function

// Function-under-test declaration
int nc_get_att_string(int ncid, int varid, const char *name, char **value);

int LLVMFuzzerTestOneInput_446(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract meaningful values
    if (size < 10) {
        return 0;
    }

    // Extract integers from the input data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Extract a string for the 'name' parameter
    size_t name_len = (size < 20) ? size - 2 : 18;
    char name[20];
    memcpy(name, data + 2, name_len);
    name[name_len] = '\0'; // Null-terminate the string

    // Prepare a pointer for the 'value' parameter
    char *value = NULL;

    // Call the function-under-test
    nc_get_att_string(ncid, varid, name, &value);

    // Free the allocated memory if any
    if (value != NULL) {
        free(value);
    }

    return 0;
}