#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_449(const uint8_t *data, size_t size) {
    // Declare all variables before using them
    int ncid;
    int varid;
    char var_name[NC_MAX_NAME + 1]; // Ensure the buffer is large enough for the variable name
    nc_type var_type;
    int ndims;
    int natts;
    int dimids[NC_MAX_VAR_DIMS];

    // Check if the size is sufficient to extract meaningful data for ncid and varid
    if (size < sizeof(int) * 2) {
        return 0; // Not enough data to proceed
    }

    // Extract ncid and varid from the input data
    memcpy(&ncid, data, sizeof(int));
    memcpy(&varid, data + sizeof(int), sizeof(int));

    // Initialize var_name with some data from the input
    size_t copy_size = size - sizeof(int) * 2 < NC_MAX_NAME ? size - sizeof(int) * 2 : NC_MAX_NAME;
    memcpy(var_name, data + sizeof(int) * 2, copy_size);
    var_name[copy_size] = '\0'; // Null-terminate the string

    // Call the function-under-test
    nc_inq_var(ncid, varid, var_name, &var_type, &ndims, dimids, &natts);

    return 0;
}