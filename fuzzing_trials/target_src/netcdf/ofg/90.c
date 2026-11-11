#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

// Function-under-test declaration
int nc_get_att_longlong(int ncid, int varid, const char *name, long long *value);

int LLVMFuzzerTestOneInput_90(const uint8_t *data, size_t size) {
    // Initialize parameters for nc_get_att_longlong
    int ncid = 1; // Example non-zero integer for netCDF ID
    int varid = 1; // Example non-zero integer for variable ID

    // Ensure there's enough data to extract a string
    if (size < 2) return 0;

    // Use part of the data as a string for the 'name' parameter
    size_t name_len = data[0] % (size - 1) + 1; // Ensure name_len is within bounds
    char *name = (char *)malloc(name_len + 1);
    if (!name) return 0;
    memcpy(name, data + 1, name_len);
    name[name_len] = '\0'; // Null-terminate the string

    // Allocate memory for the long long value
    long long value;

    // Call the function-under-test
    nc_get_att_longlong(ncid, varid, name, &value);

    // Free allocated memory
    free(name);

    return 0;
}