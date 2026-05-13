#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_185(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) + sizeof(int) * 2) {
        return 0;
    }

    // Initialize parameters for nc_put_vars
    int ncid = 0; // NetCDF file ID, typically obtained from nc_open or nc_create
    int varid = 0; // Variable ID, typically obtained from nc_inq_varid

    // Extract size_t values from the data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    
    // Extract ptrdiff_t value from the data
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);

    // The remaining data is used as the void pointer input
    const void *value = (const void *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Create a dummy NetCDF file and variable to ensure the function-under-test is invoked meaningfully
    int retval;
    retval = nc_create("dummy.nc", NC_CLOBBER, &ncid);
    if (retval != NC_NOERR) {
        return 0;
    }

    retval = nc_def_var(ncid, "dummy_var", NC_INT, 0, NULL, &varid);
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

    // Call the function-under-test with meaningful parameters
    nc_put_vars(ncid, varid, start, count, stride, value);

    // Close the NetCDF file
    nc_close(ncid);

    return 0;
}