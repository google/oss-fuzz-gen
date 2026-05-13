// This fuzz driver is generated for library netcdf, aiming to fuzz the following functions:
// nc_open at dfile.c:698:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_inq_ncid at dgroup.c:58:5 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_inq_varid at dvarinq.c:60:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_var_ulonglong at dvarget.c:1116:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_inq_varid at dvarinq.c:60:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_var at dvarget.c:1038:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_5(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there is at least some data

    write_dummy_file(Data, Size);

    int ncid;
    int retval = nc_open("./dummy_file", NC_NOWRITE, &ncid);
    if (retval != NC_NOERR) {
        nc_strerror(retval);
        return 0;
    }

    int grp_ncid;
    retval = nc_inq_ncid(ncid, NULL, &grp_ncid);
    nc_strerror(retval);

    int varid;
    retval = nc_inq_varid(ncid, "variable_name", &varid);
    nc_strerror(retval);

    unsigned long long data_ulonglong;
    retval = nc_get_var_ulonglong(ncid, varid, &data_ulonglong);
    nc_strerror(retval);

    retval = nc_inq_varid(ncid, "variable_name", &varid);
    nc_strerror(retval);

    retval = nc_get_var(ncid, varid, &data_ulonglong);
    nc_strerror(retval);

    retval = nc_close(ncid);
    nc_strerror(retval);

    return 0;
}