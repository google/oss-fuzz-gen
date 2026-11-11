// This fuzz driver is generated for library netcdf, aiming to fuzz the following functions:
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_create at dfile.c:432:1 in netcdf.h
// nc_def_dim at ddim.c:121:1 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_def_var at dvar.c:216:1 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_set_fill at dfile.c:1508:1 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_enddef at dfile.c:1061:1 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_put_vara_schar at dvarput.c:654:1 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_open at dfile.c:698:1 in netcdf.h
// nc_get_vara_schar at dvarget.c:766:1 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#define FILE_NAME "./dummy_file"
#define DIM_NAME "dim"
#define VAR_NAME "var"
#define DIM_LEN 10
#define VAR_COUNT 2

static void write_dummy_file() {
    FILE *file = fopen(FILE_NAME, "w");
    if (file) {
        fputs("dummy", file);
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_4(const uint8_t *Data, size_t Size) {
    int retval;
    int ncid, dimids[VAR_COUNT], varids[VAR_COUNT];
    size_t start[1] = {0};
    size_t count[1] = {DIM_LEN};
    signed char data[DIM_LEN];
    int old_mode;

    // Initialize data array with fuzzing input
    for (size_t i = 0; i < DIM_LEN && i < Size; i++) {
        data[i] = Data[i];
    }

    write_dummy_file();

    // nc_create
    retval = nc_create(FILE_NAME, NC_CLOBBER, &ncid);
    if (retval != NC_NOERR) return retval;

    // nc_def_dim
    for (int i = 0; i < VAR_COUNT; i++) {
        retval = nc_def_dim(ncid, DIM_NAME, DIM_LEN, &dimids[i]);
        if (retval != NC_NOERR) {
            nc_close(ncid);
            return retval;
        }
    }

    // nc_def_var
    for (int i = 0; i < VAR_COUNT; i++) {
        retval = nc_def_var(ncid, VAR_NAME, NC_BYTE, 1, dimids, &varids[i]);
        if (retval != NC_NOERR) {
            nc_close(ncid);
            return retval;
        }
    }

    // nc_set_fill
    retval = nc_set_fill(ncid, NC_NOFILL, &old_mode);
    if (retval != NC_NOERR) {
        nc_close(ncid);
        return retval;
    }

    // nc_enddef
    retval = nc_enddef(ncid);
    if (retval != NC_NOERR) {
        nc_close(ncid);
        return retval;
    }

    // nc_put_vara_schar
    for (int i = 0; i < VAR_COUNT; i++) {
        retval = nc_put_vara_schar(ncid, varids[i], start, count, data);
        if (retval != NC_NOERR) {
            nc_close(ncid);
            return retval;
        }
    }

    // nc_close
    retval = nc_close(ncid);
    if (retval != NC_NOERR) return retval;

    // nc_open
    retval = nc_open(FILE_NAME, NC_NOWRITE, &ncid);
    if (retval != NC_NOERR) return retval;

    // nc_get_vara_schar
    signed char output[DIM_LEN];
    for (int i = 0; i < VAR_COUNT; i++) {
        retval = nc_get_vara_schar(ncid, varids[i], start, count, output);
        if (retval != NC_NOERR) {
            nc_close(ncid);
            return retval;
        }
    }

    // nc_close
    retval = nc_close(ncid);
    return retval;
}