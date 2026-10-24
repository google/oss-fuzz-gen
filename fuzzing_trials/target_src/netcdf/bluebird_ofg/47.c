#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_47(const uint8_t *data, size_t size) {
    int ncid, varid;
    int retval;

    // Create a new netCDF file in memory
    if ((retval = nc_create_mem("fuzz_test.nc", NC_CLOBBER, 0, NULL, &ncid))) {
        return 0;
    }

    // Define a dimension
    size_t dim_len = 10; // Example dimension length
    int dimid;
    if ((retval = nc_def_dim(ncid, "dim", dim_len, &dimid))) {
        nc_close(ncid);
        return 0;
    }

    // Define a variable
    if ((retval = nc_def_var(ncid, "var", NC_USHORT, 1, &dimid, &varid))) {
        nc_close(ncid);
        return 0;
    }

    // End define mode
    if ((retval = nc_enddef(ncid))) {
        nc_close(ncid);
        return 0;
    }

    // Ensure there is enough data to initialize the parameters
    if (size < sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2 + sizeof(unsigned short) * dim_len) {
        nc_close(ncid);
        return 0;
    }

    // Initialize start, count, stride, imap, and value
    const size_t start[] = {0}; // Start at the beginning
    const size_t count[] = {dim_len}; // Cover the whole dimension
    const ptrdiff_t stride[] = {1}; // No stride
    const ptrdiff_t imap[] = {1}; // No map
    const unsigned short *value = (const unsigned short *)(data);

    // Call the function-under-test
    nc_put_varm_ushort(ncid, varid, start, count, stride, imap, value);

    // Close the netCDF file
    nc_close(ncid);

    return 0;
}