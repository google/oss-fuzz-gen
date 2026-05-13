#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "netcdf.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy content", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_6(const uint8_t *Data, size_t Size) {
    int ncid, dimid, varid, varid2;
    int ret;
    size_t index = 0;
    double value = 0.0;

    // Prepare the dummy file
    write_dummy_file();

    // Create a netCDF file
    ret = nc_create("./dummy_file", NC_CLOBBER, &ncid);
    if (ret != NC_NOERR) {
        fprintf(stderr, "Error in nc_create: %s\n", nc_strerror(ret));
        return 0;
    }

    // Set fill mode
    int old_mode;
    ret = nc_set_fill(ncid, NC_FILL, &old_mode);
    if (ret != NC_NOERR) {
        fprintf(stderr, "Error in nc_set_fill: %s\n", nc_strerror(ret));
        nc_close(ncid);
        return 0;
    }

    // Define a dimension
    ret = nc_def_dim(ncid, "dim", 10, &dimid);
    if (ret != NC_NOERR) {
        fprintf(stderr, "Error in nc_def_dim: %s\n", nc_strerror(ret));
        nc_close(ncid);
        return 0;
    }

    // Define a variable
    ret = nc_def_var(ncid, "var", NC_DOUBLE, 1, &dimid, &varid);
    if (ret != NC_NOERR) {
        fprintf(stderr, "Error in nc_def_var (var): %s\n", nc_strerror(ret));
        nc_close(ncid);
        return 0;
    }

    // Define another variable
    ret = nc_def_var(ncid, "var2", NC_DOUBLE, 1, &dimid, &varid2);
    if (ret != NC_NOERR) {
        fprintf(stderr, "Error in nc_def_var (var2): %s\n", nc_strerror(ret));
        nc_close(ncid);
        return 0;
    }

    // End define mode
    ret = nc_enddef(ncid);
    if (ret != NC_NOERR) {
        fprintf(stderr, "Error in nc_enddef: %s\n", nc_strerror(ret));
        nc_close(ncid);
        return 0;
    }

    // Put a value into the variable
    ret = nc_put_var1_double(ncid, varid, &index, &value);
    if (ret != NC_NOERR) {
        fprintf(stderr, "Error in nc_put_var1_double: %s\n", nc_strerror(ret));
        nc_close(ncid);
        return 0;
    }

    // Close the netCDF file
    ret = nc_close(ncid);
    if (ret != NC_NOERR) {
        fprintf(stderr, "Error in nc_close: %s\n", nc_strerror(ret));
        return 0;
    }

    return 0;
}