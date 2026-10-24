#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_180(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the parameters
    int ncid = 0; // NetCDF file ID, assuming 0 for fuzzing
    int varid = 0; // Variable ID, assuming 0 for fuzzing
    size_t index = 0; // Index for the variable, assuming 0 for fuzzing
    const size_t *start = &index; // Pointer to the index

    // Ensure the data size is sufficient for at least one string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the string and ensure it's null-terminated
    char *str = (char *)malloc(size + 1);
    if (str == NULL) {
        return 0;
    }
    memcpy(str, data, size);
    str[size] = '\0';

    const char *str_array[1] = {str}; // Array of string pointers

    // Call the function-under-test
    nc_put_var1_string(ncid, varid, start, str_array);

    // Free allocated memory
    free(str);

    return 0;
}