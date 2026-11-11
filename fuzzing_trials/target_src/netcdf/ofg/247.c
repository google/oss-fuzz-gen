#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_247(const uint8_t *data, size_t size) {
    // Ensure there's enough data for at least one unsigned char
    if (size < 1) {
        return 0;
    }

    // Create a new NetCDF file in memory
    int ncid;
    if (nc_create_mem("fuzz_test.nc", NC_CLOBBER, 1024 * 1024, NULL, &ncid) != NC_NOERR) {
        return 0;
    }

    // Define dimensions
    int dimids[2];
    if (nc_def_dim(ncid, "dim1", NC_UNLIMITED, &dimids[0]) != NC_NOERR ||
        nc_def_dim(ncid, "dim2", 1, &dimids[1]) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // Define a variable
    int varid;
    if (nc_def_var(ncid, "var", NC_UBYTE, 2, dimids, &varid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // Exit define mode
    if (nc_enddef(ncid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // Define start and count for the variable
    size_t start[2] = {0, 0}; // Starting indices for each dimension
    size_t count[2] = {1, 1}; // Count of elements for each dimension

    // Use the provided data as the array of unsigned char
    const unsigned char *ubdata = data;

    // Call the function-under-test
    nc_put_vara_ubyte(ncid, varid, start, count, ubdata);

    // Close the NetCDF file
    nc_close(ncid);

    return 0;
}