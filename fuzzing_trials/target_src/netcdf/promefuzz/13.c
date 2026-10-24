// This fuzz driver is generated for library netcdf, aiming to fuzz the following functions:
// nc_create at dfile.c:432:1 in netcdf.h
// nc_set_fill at dfile.c:1508:1 in netcdf.h
// nc_def_dim at ddim.c:121:1 in netcdf.h
// nc_def_var at dvar.c:216:1 in netcdf.h
// nc_def_var_chunking at dvar.c:732:1 in netcdf.h
// nc_def_var_filter at dfilter.c:126:1 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

static void write_dummy_file(const uint8_t *Data, size_t Size) {
    FILE *file = fopen("./dummy_file", "wb");
    if (file) {
        fwrite(Data, 1, Size, file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_13(const uint8_t *Data, size_t Size) {
    if (Size < 1) return 0; // Ensure there's at least some data

    int ncid;
    int retval;
    int dimid;
    int varid;
    int old_mode;
    size_t chunk_size = 1;
    unsigned int filter_id = 1;
    unsigned int params[1] = {0};
    
    // Step 1: Create a dummy file
    write_dummy_file(Data, Size);

    // Step 2: nc_create
    retval = nc_create("./dummy_file", NC_CLOBBER, &ncid);
    if (retval != NC_NOERR) return 0;

    // Step 3: nc_set_fill
    retval = nc_set_fill(ncid, NC_FILL, &old_mode);
    if (retval != NC_NOERR) goto cleanup;

    // Step 4: nc_def_dim
    retval = nc_def_dim(ncid, "dim", 10, &dimid);
    if (retval != NC_NOERR) goto cleanup;

    // Step 5: nc_def_var
    retval = nc_def_var(ncid, "var", NC_INT, 1, &dimid, &varid);
    if (retval != NC_NOERR) goto cleanup;

    // Step 6: nc_def_var_chunking
    retval = nc_def_var_chunking(ncid, varid, NC_CHUNKED, &chunk_size);
    if (retval != NC_NOERR) goto cleanup;

    // Step 7: nc_def_var_filter
    retval = nc_def_var_filter(ncid, varid, filter_id, 1, params);
    if (retval != NC_NOERR) goto cleanup;

cleanup:
    nc_close(ncid);
    return 0;
}