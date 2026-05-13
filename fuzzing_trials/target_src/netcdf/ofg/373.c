#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

// Function-under-test declaration
int nc_def_var_filter(int ncid, int varid, unsigned int id, size_t nparams, const unsigned int *params);

int LLVMFuzzerTestOneInput_373(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for at least one unsigned int parameter
    if (size < sizeof(unsigned int)) {
        return 0;
    }

    // Initialize parameters for nc_def_var_filter
    int ncid = 1; // Example non-zero file ID
    int varid = 1; // Example non-zero variable ID
    unsigned int id = 1; // Example non-zero filter ID
    size_t nparams = size / sizeof(unsigned int); // Number of parameters

    // Allocate memory for the parameters array
    unsigned int *params = (unsigned int *)data;

    // Call the function-under-test
    nc_def_var_filter(ncid, varid, id, nparams, params);

    return 0;
}