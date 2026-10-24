#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_448(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid = 1; // Example non-null integer
    int varid = 1; // Example non-null integer
    char name[NC_MAX_NAME + 1]; // Buffer for variable name
    nc_type xtype; // Variable to store the type of the variable
    int ndims; // Variable to store the number of dimensions
    int dimids[NC_MAX_DIMS]; // Array to store dimension IDs
    int natts; // Variable to store the number of attributes

    // Ensure the name is null-terminated
    if (size > 0) {
        size_t name_size = (size < NC_MAX_NAME) ? size : NC_MAX_NAME;
        memcpy(name, data, name_size);
        name[name_size] = '\0';
    } else {
        name[0] = '\0';
    }

    // Call the function-under-test
    nc_inq_var(ncid, varid, name, &xtype, &ndims, dimids, &natts);

    return 0;
}