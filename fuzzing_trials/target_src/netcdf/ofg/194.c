#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// Assuming the function is declared in a header file
// #include "netcdf.h" // Include the appropriate header file for the function declaration

int nc_get_var1_string(int, int, const size_t *, char **);

int LLVMFuzzerTestOneInput_194(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient to extract parameters
    if (size < sizeof(size_t) + 2 * sizeof(int)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    size_t index = *((size_t *)(data + 2 * sizeof(int)));

    // Ensure the string pointer is not NULL
    char *string = (char *)malloc(256); // Allocate memory for the string
    if (string == NULL) {
        return 0;
    }
    memset(string, 0, 256); // Initialize the memory to zero

    // Call the function-under-test
    nc_get_var1_string(ncid, varid, &index, &string);

    // Free the allocated memory
    free(string);

    return 0;
}