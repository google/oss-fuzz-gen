#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "netcdf.h"
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fputs("dummy content", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_23(const uint8_t *Data, size_t Size) {
    if (Size < sizeof(int) + 2 * sizeof(size_t) + 2 * sizeof(int)) {
        return 0;
    }

    write_dummy_file();

    int format = *(int *)Data;
    Data += sizeof(int);

    char dim_name[256];
    snprintf(dim_name, sizeof(dim_name), "dim_%zu", *(size_t *)Data);
    Data += sizeof(size_t);

    size_t dim_length = *(size_t *)Data;
    Data += sizeof(size_t);

    char var_name[256];
    snprintf(var_name, sizeof(var_name), "var_%zu", *(size_t *)Data);
    Data += sizeof(size_t);

    int ncid, dimid, varid;
    int ret;

    ret = nc_set_default_format(format, NULL);
    if (ret != NC_NOERR) {
        fprintf(stderr, "nc_set_default_format error: %s\n", nc_strerror(ret));
        return 0;
    }

    ret = nc_create("./dummy_file", NC_CLOBBER, &ncid);
    if (ret != NC_NOERR) {
        fprintf(stderr, "nc_create error: %s\n", nc_strerror(ret));
        return 0;
    }
    fprintf(stderr, "nc_create: %s\n", nc_strerror(ret));


    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 2 of nc_def_dim
    ret = nc_def_dim(ncid, dim_name, NC_ENDIAN_LITTLE, &dimid);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    if (ret != NC_NOERR) {
        fprintf(stderr, "nc_def_dim error: %s\n", nc_strerror(ret));
        nc_close(ncid);
        return 0;
    }
    fprintf(stderr, "nc_def_dim: %s\n", nc_strerror(ret));


    // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 1 of nc_def_dim
    ret = nc_def_dim(ncid, (const char *)Data, dim_length, &dimid);
    // End mutation: Producer.REPLACE_ARG_MUTATOR


    if (ret != NC_NOERR) {
        fprintf(stderr, "nc_def_dim (2nd) error: %s\n", nc_strerror(ret));

        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of nc_close
        nc_close(NC_FORMATX_UDF6);
        // End mutation: Producer.REPLACE_ARG_MUTATOR


        return 0;
    }

    // Begin mutation: Producer.APPEND_MUTATOR - Incorporated data flow from nc_def_dim to nc_inq_attlen

    int ret_nc_inq_attlen_hvxmd = nc_inq_attlen(NC_FORMATX_UNDEFINED, NC_FILL, (const char *)"w", (size_t *)&ret);
    if (ret_nc_inq_attlen_hvxmd < 0){
    	return 0;
    }

    // End mutation: Producer.APPEND_MUTATOR

    fprintf(stderr, "nc_def_dim (2nd): %s\n", nc_strerror(ret));

    ret = nc_def_var(ncid, var_name, NC_FLOAT, 1, &dimid, &varid);
    if (ret != NC_NOERR) {
        fprintf(stderr, "nc_def_var error: %s\n", nc_strerror(ret));
        nc_close(ncid);
        return 0;
    }
    fprintf(stderr, "nc_def_var: %s\n", nc_strerror(ret));


    // Begin mutation: Producer.REPLACE_FUNC_MUTATOR - Replaced function nc_enddef with nc_abort
    ret = nc_abort(ncid);
    // End mutation: Producer.REPLACE_FUNC_MUTATOR


    if (ret != NC_NOERR) {
        fprintf(stderr, "nc_enddef error: %s\n", nc_strerror(ret));
        nc_close(ncid);
        return 0;
    }
    fprintf(stderr, "nc_enddef: %s\n", nc_strerror(ret));

    float data = 0.0f;
    if (Size >= sizeof(float)) {
        data = *(float *)Data;
    }

    ret = nc_put_var_float(ncid, varid, &data);
    if (ret != NC_NOERR) {
        fprintf(stderr, "nc_put_var_float error: %s\n", nc_strerror(ret));

        // Begin mutation: Producer.REPLACE_ARG_MUTATOR - Replaced argument 0 of nc_close
        nc_close(-1);
        // End mutation: Producer.REPLACE_ARG_MUTATOR


        return 0;
    }
    fprintf(stderr, "nc_put_var_float: %s\n", nc_strerror(ret));

    ret = nc_close(ncid);
    if (ret != NC_NOERR) {
        fprintf(stderr, "nc_close error: %s\n", nc_strerror(ret));
    }
    fprintf(stderr, "nc_close: %s\n", nc_strerror(ret));

    return 0;
}