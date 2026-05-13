#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include "netcdf.h"

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "netCDF dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_15(const uint8_t *Data, size_t Size) {
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