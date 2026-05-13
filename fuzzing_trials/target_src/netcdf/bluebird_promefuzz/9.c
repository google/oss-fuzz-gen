#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "netcdf.h"

static void write_dummy_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file) {
        fprintf(file, "dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(nc_type)) return 0;

    // Prepare the environment
    const char *filename = "./dummy_file";
    write_dummy_file(filename);

    int ncid, varid, retval;
    nc_type xtype = *(nc_type *)Data;
    size_t offset = 0;
    unsigned long long ulonglong_value = 0;
    const char *name = "dummy_name";
    int dimidsp[1] = {0};
    size_t compound_size = sizeof(unsigned long long);

    // Open a new netCDF file for writing
    if ((retval = nc_create(filename, NC_CLOBBER, &ncid)))
        return 0;

    // Fuzzing sequence
    const char *errmsg;

    errmsg = nc_strerror(retval);
    nc_put_var_ulonglong(ncid, varid, &ulonglong_value);
    errmsg = nc_strerror(retval);
    nc_def_compound(ncid, compound_size, name, &xtype);
    errmsg = nc_strerror(retval);
    nc_insert_compound(ncid, xtype, name, offset, xtype);
    errmsg = nc_strerror(retval);
    nc_insert_compound(ncid, xtype, name, offset, xtype);
    errmsg = nc_strerror(retval);
    nc_def_var(ncid, name, xtype, 1, dimidsp, &varid);
    errmsg = nc_strerror(retval);
    nc_put_var(ncid, varid, &ulonglong_value);
    errmsg = nc_strerror(retval);
    nc_close(ncid);
    errmsg = nc_strerror(retval);

    return 0;
}