// This fuzz driver is generated for library netcdf, aiming to fuzz the following functions:
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_put_att_text at dattput.c:153:5 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_def_dim at ddim.c:121:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_def_dim at ddim.c:121:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_def_var at dvar.c:216:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_put_att_text at dattput.c:153:5 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_put_att_float at dattput.c:426:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_enddef at dfile.c:1061:1 in netcdf.h
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
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();

    int ncid = 0; // Dummy ncid
    int varid = 0; // Dummy varid
    int dimid = 0; // Dummy dimid
    nc_type xtype = NC_INT; // Dummy nc_type
    const char *att_name = "attribute";
    const char *dim_name = "dimension";
    const char *var_name = "variable";
    size_t len = 4; // Dummy length
    float float_data[] = {1.0, 2.0, 3.0, 4.0}; // Dummy float data
    const char *text_data = "text";

    // nc_strerror
    const char* err_msg = nc_strerror(Data[0]);
    (void)err_msg;

    // nc_put_att_text
    int ret = nc_put_att_text(ncid, varid, att_name, len, text_data);
    if (ret != NC_NOERR) return 0;

    // nc_strerror
    err_msg = nc_strerror(ret);
    (void)err_msg;

    // nc_def_dim
    ret = nc_def_dim(ncid, dim_name, len, &dimid);
    if (ret != NC_NOERR) return 0;

    // nc_strerror
    err_msg = nc_strerror(ret);
    (void)err_msg;

    // nc_def_dim again
    ret = nc_def_dim(ncid, dim_name, len, &dimid);
    if (ret != NC_NOERR) return 0;

    // nc_strerror
    err_msg = nc_strerror(ret);
    (void)err_msg;

    // nc_def_var
    ret = nc_def_var(ncid, var_name, xtype, 1, &dimid, &varid);
    if (ret != NC_NOERR) return 0;

    // nc_strerror
    err_msg = nc_strerror(ret);
    (void)err_msg;

    // nc_put_att_text again
    ret = nc_put_att_text(ncid, varid, att_name, len, text_data);
    if (ret != NC_NOERR) return 0;

    // nc_strerror
    err_msg = nc_strerror(ret);
    (void)err_msg;

    // nc_put_att_float
    ret = nc_put_att_float(ncid, varid, att_name, xtype, len, float_data);
    if (ret != NC_NOERR) return 0;

    // nc_strerror
    err_msg = nc_strerror(ret);
    (void)err_msg;

    // nc_enddef
    ret = nc_enddef(ncid);
    if (ret != NC_NOERR) return 0;

    // nc_strerror
    err_msg = nc_strerror(ret);
    (void)err_msg;

    return 0;
}