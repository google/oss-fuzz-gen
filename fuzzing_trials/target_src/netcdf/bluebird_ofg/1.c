#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"
#include <string.h>

int LLVMFuzzerTestOneInput_1(const uint8_t *data, size_t size) {
    // Ensure that the input size is sufficient for our needs
    if (size < sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(double)) {
        return 0;
    }

    // Extract the first two integers from the data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));

    // Extract size_t values for start and count
    const size_t *start = (const size_t *)(data + sizeof(int) * 2);
    const size_t *count = (const size_t *)(data + sizeof(int) * 2 + sizeof(size_t));

    // Extract ptrdiff_t value for stride
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(int) * 2 + sizeof(size_t) * 2);

    // Extract double value
    const double *value = (const double *)(data + sizeof(int) * 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Create a mock or temporary NetCDF file to ensure the function can be tested
    int retval;
    int dimid;
    int varid_created;
    size_t dimlen = 10; // Arbitrary dimension length for testing

    // Create a new NetCDF file in memory
    retval = nc_create("test.nc", NC_CLOBBER | NC_INMEMORY, &ncid);
    if (retval != NC_NOERR) return 0;

    // Define a dimension
    retval = nc_def_dim(ncid, "dim", dimlen, &dimid);
    if (retval != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // Define a variable
    retval = nc_def_var(ncid, "var", NC_DOUBLE, 1, &dimid, &varid_created);
    if (retval != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // End define mode
    retval = nc_enddef(ncid);
    if (retval != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // Ensure that varid matches the created variable
    if (varid != varid_created) {
        varid = varid_created;
    }

    // Call the function under test with the created NetCDF environment
    retval = nc_put_vars_double(ncid, varid, start, count, stride, value);

    // Close the NetCDF file
    nc_close(ncid);

    return 0;
}