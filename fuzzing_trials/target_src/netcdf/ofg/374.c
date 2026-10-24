#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

// Assume the function is declared in a header file
int nc_def_var_filter(int ncid, int varid, unsigned int id, size_t nparams, const unsigned int *params);

int LLVMFuzzerTestOneInput_374(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 1; // Example non-null value
    int varid = 1; // Example non-null value
    unsigned int id = 1; // Example non-null value
    size_t nparams = size / sizeof(unsigned int);

    // Allocate memory for params and copy data
    unsigned int *params = (unsigned int *)malloc(nparams * sizeof(unsigned int));
    if (params == NULL) {
        return 0; // Exit if memory allocation fails
    }

    // Copy data into params
    for (size_t i = 0; i < nparams; i++) {
        if (i < size / sizeof(unsigned int)) {
            params[i] = ((unsigned int *)data)[i];
        } else {
            params[i] = 0; // Fill remaining with zeros if data is insufficient
        }
    }

    // Call the function-under-test
    nc_def_var_filter(ncid, varid, id, nparams, params);

    // Free allocated memory
    free(params);

    return 0;
}