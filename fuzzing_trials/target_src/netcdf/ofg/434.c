#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_434(const uint8_t *data, size_t size) {
    // Declare and initialize necessary variables
    int ncid = 0;  // NetCDF file ID
    int varid = 0; // Variable ID

    // Ensure there's enough data to extract dimensions and values
    if (size < 4 * sizeof(size_t) + sizeof(short)) {
        return 0;
    }

    // Extract dimensions from the input data
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + 2 * sizeof(size_t));

    // Extract short values from the input data
    const short *short_values = (const short *)(data + 4 * sizeof(size_t));

    // Create a NetCDF file and a variable to ensure the function is invoked meaningfully
    if (nc_create("fuzz_temp.nc", NC_CLOBBER, &ncid) != NC_NOERR) {
        return 0;
    }

    int dimids[1];
    if (nc_def_dim(ncid, "dim", NC_UNLIMITED, &dimids[0]) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    if (nc_def_var(ncid, "var", NC_SHORT, 1, dimids, &varid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    if (nc_enddef(ncid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // Call the function-under-test
    nc_put_vara_short(ncid, varid, start, count, short_values);

    // Close the NetCDF file
    nc_close(ncid);

    return 0;
}