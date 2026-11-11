#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "netcdf.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "dummy content");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_1(const uint8_t *Data, size_t Size) {
    int ncid, dimid, varid;
    size_t len = 10;
    float values[10] = {0.0};
    size_t start[1] = {0};
    size_t count[1] = {10};

    write_dummy_file();

    if (nc_create("./dummy_file", NC_CLOBBER, &ncid) != NC_NOERR) return 0;
    nc_strerror(nc_create("./dummy_file", NC_CLOBBER, &ncid));

    if (nc_def_dim(ncid, "dim1", len, &dimid) != NC_NOERR) goto cleanup;
    nc_strerror(nc_def_dim(ncid, "dim1", len, &dimid));

    if (nc_def_dim(ncid, "dim2", len, &dimid) != NC_NOERR) goto cleanup;
    nc_strerror(nc_def_dim(ncid, "dim2", len, &dimid));

    if (nc_def_dim(ncid, "dim3", len, &dimid) != NC_NOERR) goto cleanup;
    nc_strerror(nc_def_dim(ncid, "dim3", len, &dimid));

    if (nc_def_dim(ncid, "dim4", len, &dimid) != NC_NOERR) goto cleanup;
    nc_strerror(nc_def_dim(ncid, "dim4", len, &dimid));

    if (nc_def_var(ncid, "var1", NC_FLOAT, 1, &dimid, &varid) != NC_NOERR) goto cleanup;
    nc_strerror(nc_def_var(ncid, "var1", NC_FLOAT, 1, &dimid, &varid));

    if (nc_def_var(ncid, "var2", NC_FLOAT, 1, &dimid, &varid) != NC_NOERR) goto cleanup;
    nc_strerror(nc_def_var(ncid, "var2", NC_FLOAT, 1, &dimid, &varid));

    if (nc_put_att_text(ncid, varid, "attr1", 5, "value") != NC_NOERR) goto cleanup;
    nc_strerror(nc_put_att_text(ncid, varid, "attr1", 5, "value"));

    if (nc_put_att_text(ncid, varid, "attr2", 5, "value") != NC_NOERR) goto cleanup;
    nc_strerror(nc_put_att_text(ncid, varid, "attr2", 5, "value"));

    if (nc_def_var(ncid, "var3", NC_FLOAT, 1, &dimid, &varid) != NC_NOERR) goto cleanup;
    nc_strerror(nc_def_var(ncid, "var3", NC_FLOAT, 1, &dimid, &varid));

    if (nc_def_var(ncid, "var4", NC_FLOAT, 1, &dimid, &varid) != NC_NOERR) goto cleanup;
    nc_strerror(nc_def_var(ncid, "var4", NC_FLOAT, 1, &dimid, &varid));

    if (nc_put_att_text(ncid, varid, "attr3", 5, "value") != NC_NOERR) goto cleanup;
    nc_strerror(nc_put_att_text(ncid, varid, "attr3", 5, "value"));

    if (nc_put_att_text(ncid, varid, "attr4", 5, "value") != NC_NOERR) goto cleanup;
    nc_strerror(nc_put_att_text(ncid, varid, "attr4", 5, "value"));

    if (nc_enddef(ncid) != NC_NOERR) goto cleanup;
    nc_strerror(nc_enddef(ncid));

    if (nc_put_var_float(ncid, varid, values) != NC_NOERR) goto cleanup;
    nc_strerror(nc_put_var_float(ncid, varid, values));

    if (nc_put_var_float(ncid, varid, values) != NC_NOERR) goto cleanup;
    nc_strerror(nc_put_var_float(ncid, varid, values));

    if (nc_put_vara_float(ncid, varid, start, count, values) != NC_NOERR) goto cleanup;
    nc_strerror(nc_put_vara_float(ncid, varid, start, count, values));

    if (nc_put_vara_float(ncid, varid, start, count, values) != NC_NOERR) goto cleanup;
    nc_strerror(nc_put_vara_float(ncid, varid, start, count, values));

cleanup:
    if (nc_close(ncid) != NC_NOERR) return 0;
    nc_strerror(nc_close(ncid));

    return 0;
}