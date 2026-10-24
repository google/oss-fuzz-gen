#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

// Assuming the function nc_get_var_int_273 is declared in some header file
// #include "netcdf.h" // Example header file where nc_get_var_int_273 might be declared

// Mock function definition for nc_get_var_int_273, replace with actual function declaration if available
int nc_get_var_int_273(int ncid, int varid, int *ip) {
    // Mock implementation
    return 0;
}

int LLVMFuzzerTestOneInput_273(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract two integers
    if (size < sizeof(int) * 2) {
        return 0;
    }

    // Extracting two integers from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    // Allocate memory for the integer pointer
    int *ip = (int *)malloc(sizeof(int));
    if (ip == NULL) {
        return 0; // Handle memory allocation failure
    }

    // Call the function-under-test
    int result = nc_get_var_int_273(ncid, varid, ip);

    // Free the allocated memory
    free(ip);

    return 0;
}