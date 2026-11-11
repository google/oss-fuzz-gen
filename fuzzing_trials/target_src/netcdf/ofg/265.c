#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

// Function to create a mock NetCDF file and return its ID
int create_mock_netcdf(int *ncid) {
    // Create a new NetCDF file in memory
    int retval = nc_create_mem("mock.nc", NC_CLOBBER, 0, NULL, ncid);
    if (retval != NC_NOERR) return retval;

    // Define a dimension
    int dimid;
    retval = nc_def_dim(*ncid, "dim", NC_UNLIMITED, &dimid);
    if (retval != NC_NOERR) return retval;

    // Define a variable
    int varid;
    retval = nc_def_var(*ncid, "var", NC_INT, 1, &dimid, &varid);
    if (retval != NC_NOERR) return retval;

    // End define mode
    retval = nc_enddef(*ncid);
    if (retval != NC_NOERR) return retval;

    return NC_NOERR;
}

int LLVMFuzzerTestOneInput_265(const uint8_t *data, size_t size) {
    int ncid;
    int varid = 0; // Assume the first variable
    char name[NC_MAX_NAME + 1]; // Allocate buffer for the name with max size

    // Create a mock NetCDF file
    if (create_mock_netcdf(&ncid) != NC_NOERR) {
        return 0; // Exit if mock creation fails
    }

    // Ensure the name buffer is not NULL and has some initial content
    if (size > 0) {
        size_t copy_size = size < NC_MAX_NAME ? size : NC_MAX_NAME;
        memcpy(name, data, copy_size);
        name[copy_size] = '\0'; // Null-terminate the string
    } else {
        strcpy(name, "default_name");
    }

    // Call the function-under-test
    int result = nc_inq_varname(ncid, varid, name);

    // Close the mock NetCDF file
    nc_close(ncid);

    // The result is not used further, as we are focusing on fuzzing
    (void)result;

    return 0;
}