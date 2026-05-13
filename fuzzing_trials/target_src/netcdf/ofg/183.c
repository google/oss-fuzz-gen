#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_183(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid;
    int varid;
    const char *name = "example_attribute";
    nc_type xtype = NC_UBYTE;
    size_t len = size > 0 ? size : 1;
    unsigned char *values = (unsigned char *)malloc(len * sizeof(unsigned char));

    // Copy data into values, ensuring we don't exceed the input size
    if (size > 0) {
        memcpy(values, data, len);
    } else {
        values[0] = 0;
    }

    // Create a new NetCDF file in memory to get a valid ncid
    if (nc_create_mem("inmemory.nc", NC_CLOBBER | NC_NETCDF4, 0, NULL, &ncid) != NC_NOERR) {
        free(values);
        return 0;
    }

    // Define a variable to get a valid varid
    if (nc_def_var(ncid, "example_var", xtype, 0, NULL, &varid) != NC_NOERR) {
        nc_close(ncid);
        free(values);
        return 0;
    }

    // End define mode
    if (nc_enddef(ncid) != NC_NOERR) {
        nc_close(ncid);
        free(values);
        return 0;
    }

    // Call the function-under-test
    int result = nc_put_att_ubyte(ncid, varid, name, xtype, len, values);

    // Clean up
    nc_close(ncid);
    free(values);

    return 0;
}