#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_320(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for the inputs
    if (size < 10) {
        return 0;
    }

    // Initialize parameters for nc_def_dim
    int ncid = 0;  // Assuming a valid netCDF ID for fuzzing
    size_t dim_len = (size_t)data[0];  // Using the first byte for dimension length
    int dimid;  // Output dimension ID

    // Create a name string from data
    size_t name_len = size - 1; // Ensure there's space for the null terminator
    char *name = (char *)malloc(name_len + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 1, name_len);
    name[name_len] = '\0';  // Null-terminate the string

    // Call the function-under-test
    nc_def_dim(ncid, name, dim_len, &dimid);

    // Clean up
    free(name);

    return 0;
}