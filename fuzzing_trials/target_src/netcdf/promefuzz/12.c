// This fuzz driver is generated for library netcdf, aiming to fuzz the following functions:
// nc_open at dfile.c:698:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_inq_varid at dvarinq.c:60:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_var_float at dvarget.c:1080:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_inq_varid at dvarinq.c:60:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_vara_float at dvarget.c:801:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <netcdf.h>

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        // Write minimal valid netCDF data to the file for testing
        const char dummy_data[] = "CDF\001\0\0\0\0"; // Minimal header for netCDF
        fwrite(dummy_data, 1, sizeof(dummy_data), file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_12(const uint8_t *Data, size_t Size) {
    write_dummy_file();

    int ncid;
    int varid;
    float value;
    size_t start[1] = {0};
    size_t count[1] = {1};

    // Attempt to open the dummy netCDF file
    int retval = nc_open("./dummy_file", NC_NOWRITE, &ncid);
    if (retval != NC_NOERR) {
        nc_strerror(retval);
        return 0;
    }

    // Try to get variable ID using fuzz data as a name
    retval = nc_inq_varid(ncid, (const char *)Data, &varid);
    nc_strerror(retval);

    // Attempt to get variable data as float
    retval = nc_get_var_float(ncid, varid, &value);
    nc_strerror(retval);

    // Try to get variable ID again to explore more states
    retval = nc_inq_varid(ncid, (const char *)Data, &varid);
    nc_strerror(retval);

    // Attempt to get array variable data as float
    retval = nc_get_vara_float(ncid, varid, start, count, &value);
    nc_strerror(retval);

    // Close the netCDF file
    retval = nc_close(ncid);
    nc_strerror(retval);

    return 0;
}