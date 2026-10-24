#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "netcdf.h"

static void write_dummy_file(const char *filename) {
    FILE *file = fopen(filename, "w");
    if (file) {
        fprintf(file, "dummy content");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_10(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    const char *file_path = "./dummy_file";
    write_dummy_file(file_path);

    int ncid, dimid1, dimid2, varid;
    int retval;

    // Create a new netCDF file
    retval = nc_create(file_path, NC_CLOBBER, &ncid);
    if (retval != NC_NOERR) {
        nc_strerror(retval);
        return 0;
    }

    // Define dimensions
    retval = nc_def_dim(ncid, "dim1", 10, &dimid1);
    if (retval != NC_NOERR) {
        nc_strerror(retval);
        nc_close(ncid);
        return 0;
    }

    retval = nc_def_dim(ncid, "dim2", 20, &dimid2);
    if (retval != NC_NOERR) {
        nc_strerror(retval);
        nc_close(ncid);
        return 0;
    }

    int dimids[2] = {dimid1, dimid2};

    // Define a variable
    retval = nc_def_var(ncid, "var1", NC_INT, 2, dimids, &varid);
    if (retval != NC_NOERR) {
        nc_strerror(retval);
        nc_close(ncid);
        return 0;
    }

    // Define chunking for the variable
    size_t chunksizes[2] = {5, 10};
    retval = nc_def_var_chunking(ncid, varid, NC_CHUNKED, chunksizes);
    if (retval != NC_NOERR) {
        nc_strerror(retval);
        nc_close(ncid);
        return 0;
    }

    // Set deflate settings for the variable
    retval = nc_def_var_deflate(ncid, varid, 1, 1, 1);
    if (retval != NC_NOERR) {
        nc_strerror(retval);
        nc_close(ncid);
        return 0;
    }

    // Write data to the variable
    int data[10][20];
    for (int i = 0; i < 10; ++i) {
        for (int j = 0; j < 20; ++j) {
            data[i][j] = (int)Data[(i * 20 + j) % Size];
        }
    }

    retval = nc_put_var_int(ncid, varid, &data[0][0]);
    if (retval != NC_NOERR) {
        nc_strerror(retval);
        nc_close(ncid);
        return 0;
    }

    // Close the netCDF file
    retval = nc_close(ncid);
    if (retval != NC_NOERR) {
        nc_strerror(retval);
        return 0;
    }

    return 0;
}