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
        fputs("dummy content", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_16(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0;

    write_dummy_file();
    
    int ncid;
    int ret;
    int dimid1, dimid2;
    int grp_id1, grp_id2;
    int var_id;
    size_t len = 10;
    nc_type xtype = NC_INT;
    
    // Create a new netCDF file
    ret = nc_create("./dummy_file", NC_CLOBBER, &ncid);
    if (ret != NC_NOERR) {
        nc_strerror(ret);
        return 0;
    }
    
    // Define dimension 1
    ret = nc_def_dim(ncid, "dim1", len, &dimid1);
    if (ret != NC_NOERR) {
        nc_strerror(ret);
    }
    
    // Define dimension 2
    ret = nc_def_dim(ncid, "dim2", len, &dimid2);
    if (ret != NC_NOERR) {
        nc_strerror(ret);
    }
    
    // Define group 1
    ret = nc_def_grp(ncid, "group1", &grp_id1);
    if (ret != NC_NOERR) {
        nc_strerror(ret);
    }
    
    // Define group 2
    ret = nc_def_grp(ncid, "group2", &grp_id2);
    if (ret != NC_NOERR) {
        nc_strerror(ret);
    }
    
    // Define a variable
    int dimids[] = {dimid1, dimid2};
    ret = nc_def_var(ncid, "var1", xtype, 2, dimids, &var_id);
    if (ret != NC_NOERR) {
        nc_strerror(ret);
    }
    
    // Close the file
    nc_close(ncid);
    
    return 0;
}