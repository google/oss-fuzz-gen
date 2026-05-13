#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Assuming the function is declared in a header file
// #include "netcdf.h"

// Mock function definition for nc_inq_varname_266
int nc_inq_varname_266(int ncid, int varid, char *name) {
    // Mock implementation for demonstration purposes
    if (name == NULL) {
        return -1; // Simulate an error if name is NULL
    }
    // Simulate copying a variable name into the provided buffer
    strcpy(name, "mock_varname");
    return 0; // Success
}

int LLVMFuzzerTestOneInput_266(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract two integers and a buffer for the name
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract two integers from the data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    // Allocate a buffer for the variable name
    char name[256]; // Assuming a max length for the variable name

    // Call the function under test
    int result = nc_inq_varname_266(ncid, varid, name);

    // Optionally, print the result and name for debugging purposes
    printf("Result: %d, Name: %s\n", result, name);

    return 0;
}