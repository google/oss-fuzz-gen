#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_278(const uint8_t *data, size_t size) {
    int ncid, varid;
    int retval;
    char attname[256]; // Attribute name buffer
    nc_type atttype; // Attribute type

    // Ensure the data size is sufficient for a null-terminated string
    if (size < 1 || size >= sizeof(attname)) {
        return 0;
    }

    // Copy data to attname and ensure null-termination
    memcpy(attname, data, size);
    attname[size] = '\0';

    // Create a new netCDF file in memory
    retval = nc_create_mem("fuzz_test.nc", NC_CLOBBER | NC_NETCDF4, 0, &ncid);
    if (retval != NC_NOERR) {
        return 0;
    }

    // Define a dimension
    retval = nc_def_dim(ncid, "dim", 10, &varid);
    if (retval != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // Define a variable
    retval = nc_def_var(ncid, "var", NC_INT, 1, &varid, &varid);
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

    // Call the function-under-test
    nc_inq_atttype(ncid, varid, attname, &atttype);

    // Close the netCDF file
    nc_close(ncid);

    return 0;
}