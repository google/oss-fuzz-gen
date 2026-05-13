#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the function nc_get_var_string_376 is declared in a header file
// #include "netcdf.h" 

// Mockup of the function-under-test for compilation purposes
int nc_get_var_string_376(int ncid, int varid, char **value) {
    // Mock implementation
    if (value == NULL) return -1;
    *value = strdup("mock_value");
    return 0;
}

int LLVMFuzzerTestOneInput_376(const uint8_t *data, size_t size) {
    if (size < 8) {
        return 0; // Not enough data to extract two integers
    }

    // Extract two integers from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + 4));

    // Allocate memory for the string pointer
    char *value = NULL;

    // Call the function-under-test
    int result = nc_get_var_string_376(ncid, varid, &value);

    // Free the allocated string if it was set
    if (value != NULL) {
        free(value);
    }

    return 0;
}