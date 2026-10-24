#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_151(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2 + sizeof(short)) {
        return 0; // Not enough data to proceed
    }

    // Create a temporary in-memory netCDF file
    int ncid;
    if (nc_create_mem("fuzz_test.nc", NC_CLOBBER, 0, NULL, &ncid) != NC_NOERR) {
        return 0; // Failed to create in-memory netCDF file
    }

    // Define a simple dimension and variable
    int dimid;
    if (nc_def_dim(ncid, "dim", NC_UNLIMITED, &dimid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    int varid;
    if (nc_def_var(ncid, "var", NC_SHORT, 1, &dimid, &varid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // End define mode
    if (nc_enddef(ncid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // Extracting values from the data buffer
    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));
    short *value = (short *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2);

    // Call the function-under-test
    nc_get_varm_short(ncid, varid, start, count, stride, imap, value);

    // Close the netCDF file
    nc_close(ncid);

    return 0;
}