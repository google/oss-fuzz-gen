// This fuzz driver is generated for library netcdf, aiming to fuzz the following functions:
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_put_var_int at dvarput.c:952:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_open at dfile.c:698:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_inq_varid at dvarinq.c:60:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_var_int at dvarget.c:1068:1 in netcdf.h
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
#include <string.h>
#include <netcdf.h>

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "netCDF dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_11(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) * 3) return 0;

    write_dummy_file();

    int ncid, varid;
    int mode = NC_NOWRITE;
    int input_var = *(int *)Data;
    int output_var;

    // nc_strerror
    const char *error_str = nc_strerror(NC_NOERR);
    (void)error_str; // suppress unused variable warning

    // nc_put_var_int
    int ret = nc_put_var_int(ncid, varid, &input_var);
    error_str = nc_strerror(ret);

    // nc_close
    ret = nc_close(ncid);
    error_str = nc_strerror(ret);

    // nc_open
    ret = nc_open("./dummy_file", mode, &ncid);
    error_str = nc_strerror(ret);

    // nc_inq_varid
    ret = nc_inq_varid(ncid, "dummy_var", &varid);
    error_str = nc_strerror(ret);

    // nc_get_var_int
    ret = nc_get_var_int(ncid, varid, &output_var);
    error_str = nc_strerror(ret);

    // nc_close
    ret = nc_close(ncid);
    error_str = nc_strerror(ret);

    return 0;
}