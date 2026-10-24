// This fuzz driver is generated for library netcdf, aiming to fuzz the following functions:
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_open at dfile.c:698:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_inq at dfile.c:1669:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_inq_varid at dvarinq.c:60:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_inq_varid at dvarinq.c:60:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_var_float at dvarget.c:1080:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_var_float at dvarget.c:1080:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_inq_varid at dvarinq.c:60:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_inq_varid at dvarinq.c:60:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_var_float at dvarget.c:1080:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_var_float at dvarget.c:1080:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_att_text at dattget.c:222:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_att_text at dattget.c:222:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_att_text at dattget.c:222:1 in netcdf.h
// nc_strerror at derror.c:87:13 in netcdf.h
// nc_get_att_text at dattget.c:222:1 in netcdf.h
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
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void handle_error(int status) {
    if (status != NC_NOERR) {
        fprintf(stderr, "%s\n", nc_strerror(status));
        exit(EXIT_FAILURE);
    }
}

int LLVMFuzzerTestOneInput_14(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    // Prepare dummy file
    const char *dummy_file = "./dummy_file";
    FILE *file = fopen(dummy_file, "wb");
    if (!file) return 0;
    fwrite(Data, 1, Size, file);
    fclose(file);

    int ncid;
    int status = nc_open(dummy_file, NC_NOWRITE, &ncid);
    if (status != NC_NOERR) {
        nc_strerror(status);
        return 0;
    }

    int ndims, nvars, natts, unlimdimid;
    status = nc_inq(ncid, &ndims, &nvars, &natts, &unlimdimid);
    nc_strerror(status);

    int varid1, varid2;
    status = nc_inq_varid(ncid, "var1", &varid1);
    nc_strerror(status);
    status = nc_inq_varid(ncid, "var2", &varid2);
    nc_strerror(status);

    float *data1 = (float *)malloc(sizeof(float) * 10);
    float *data2 = (float *)malloc(sizeof(float) * 10);

    if (data1 && data2) {
        status = nc_get_var_float(ncid, varid1, data1);
        nc_strerror(status);
        status = nc_get_var_float(ncid, varid2, data2);
        nc_strerror(status);
    }

    free(data1);
    free(data2);

    int varid3, varid4;
    status = nc_inq_varid(ncid, "var3", &varid3);
    nc_strerror(status);
    status = nc_inq_varid(ncid, "var4", &varid4);
    nc_strerror(status);

    float *data3 = (float *)malloc(sizeof(float) * 10);
    float *data4 = (float *)malloc(sizeof(float) * 10);

    if (data3 && data4) {
        status = nc_get_var_float(ncid, varid3, data3);
        nc_strerror(status);
        status = nc_get_var_float(ncid, varid4, data4);
        nc_strerror(status);
    }

    free(data3);
    free(data4);

    char attr_text[100];
    status = nc_get_att_text(ncid, varid1, "attr1", attr_text);
    nc_strerror(status);
    status = nc_get_att_text(ncid, varid2, "attr2", attr_text);
    nc_strerror(status);
    status = nc_get_att_text(ncid, varid3, "attr3", attr_text);
    nc_strerror(status);
    status = nc_get_att_text(ncid, varid4, "attr4", attr_text);
    nc_strerror(status);

    status = nc_close(ncid);
    nc_strerror(status);

    return 0;
}