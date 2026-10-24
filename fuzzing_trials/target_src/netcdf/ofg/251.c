#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_251(const uint8_t *data, size_t size) {
    int ncid, dimid;
    char name[NC_MAX_NAME + 1]; // Buffer to store the dimension name

    // Ensure the data size is sufficient to fill the buffer
    if (size < NC_MAX_NAME) {
        return 0;
    }

    // Copy data into the name buffer, ensuring null termination
    strncpy(name, (const char *)data, NC_MAX_NAME);
    name[NC_MAX_NAME] = '\0';

    // Create a NetCDF file in memory
    if (nc_create_mem("fuzz_test.nc", NC_CLOBBER, 0, NULL, &ncid) != NC_NOERR) {
        return 0;
    }

    // Define a dimension
    if (nc_def_dim(ncid, "fuzz_dim", NC_MAX_NAME, &dimid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // End define mode
    if (nc_enddef(ncid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // Call the function-under-test
    nc_inq_dimname(ncid, dimid, name);

    // Close the NetCDF file
    nc_close(ncid);

    return 0;
}