#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h> // Include stdlib.h for malloc and free

// Mock function definition for nc_put_att_text_279
int nc_put_att_text_279(int ncid, int varid, const char *name, size_t len, const char *value) {
    // This is a mock implementation for demonstration purposes
    printf("ncid: %d, varid: %d, name: %s, len: %zu, value: %s\n", ncid, varid, name, len, value);
    return 0; // Assume success
}

int LLVMFuzzerTestOneInput_279(const uint8_t *data, size_t size) {
    int ncid = 1;  // Example non-zero ID for a netCDF file
    int varid = 1; // Example non-zero ID for a variable

    // Ensure size is at least enough to have a non-empty name and value
    if (size < 2) {
        return 0;
    }

    // Split the input data into name and value
    size_t name_len = size / 2;
    size_t value_len = size - name_len;

    // Allocate and copy data for name and value
    char *name = (char *)malloc(name_len + 1);
    char *value = (char *)malloc(value_len + 1);

    if (name == NULL || value == NULL) {
        free(name);
        free(value);
        return 0;
    }

    memcpy(name, data, name_len);
    name[name_len] = '\0'; // Null-terminate the string

    memcpy(value, data + name_len, value_len);
    value[value_len] = '\0'; // Null-terminate the string

    // Call the function-under-test
    nc_put_att_text_279(ncid, varid, name, value_len, value);

    // Clean up
    free(name);
    free(value);

    return 0;
}