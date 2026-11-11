#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>
#include <stdio.h> // Include for debugging output

int LLVMFuzzerTestOneInput_165(const uint8_t *data, size_t size) {
    // Ensure we have enough data for the parameters
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(short)) {
        return 0;
    }

    // Initialize parameters
    int ncid, varid;
    int retval;

    // Create a netCDF file in memory
    retval = nc_create("fuzz_test.nc", NC_NETCDF4 | NC_CLOBBER, &ncid);
    if (retval != NC_NOERR) {
        fprintf(stderr, "Error creating netCDF file: %s\n", nc_strerror(retval));
        return 0;
    }

    // Define a dimension
    retval = nc_def_dim(ncid, "dim", NC_UNLIMITED, NULL);
    if (retval != NC_NOERR) {
        fprintf(stderr, "Error defining dimension: %s\n", nc_strerror(retval));
        nc_close(ncid);
        return 0;
    }

    // Define a variable
    retval = nc_def_var(ncid, "var", NC_SHORT, 1, NULL, &varid);
    if (retval != NC_NOERR) {
        fprintf(stderr, "Error defining variable: %s\n", nc_strerror(retval));
        nc_close(ncid);
        return 0;
    }

    // End define mode
    retval = nc_enddef(ncid);
    if (retval != NC_NOERR) {
        fprintf(stderr, "Error ending define mode: %s\n", nc_strerror(retval));
        nc_close(ncid);
        return 0;
    }

    // Extract size_t parameters from data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));

    // Extract ptrdiff_t parameters from data
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));

    // Extract short parameter from data
    const short *value = (const short *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2);

    // Call the function-under-test
    retval = nc_put_varm_short(ncid, varid, start, count, stride, imap, value);
    if (retval != NC_NOERR) {
        fprintf(stderr, "Error writing data: %s\n", nc_strerror(retval));
    }

    // Close the netCDF file
    nc_close(ncid);

    return 0;
}