// This fuzz driver is generated for library netcdf, aiming to fuzz the following functions:
// nc_open at dfile.c:698:1 in netcdf.h
// nc_enddef at dfile.c:1061:1 in netcdf.h
// nc_put_var at dvarput.c:922:1 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_open at dfile.c:698:1 in netcdf.h
// nc_inq_varid at dvarinq.c:60:1 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
// nc_inq_var_filter at dfilter.c:167:1 in netcdf.h
// nc_inq_var_filter at dfilter.c:167:1 in netcdf.h
// nc_get_var_float at dvarget.c:1080:1 in netcdf.h
// nc_close at dfile.c:1334:1 in netcdf.h
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

static void write_dummy_file() {
    FILE *file = fopen("./dummy_file", "w");
    if (file) {
        fprintf(file, "netCDF dummy data");
        fclose(file);
    }
}

int LLVMFuzzerTestOneInput_9(const uint8_t *Data, size_t Size) {
    write_dummy_file();

    int ncid, varid;
    unsigned int filter_id;
    size_t nparams;
    unsigned int params[10]; // Arbitrary size for example
    float var_data;

    // 1. Open the dummy file
    if (nc_open("./dummy_file", NC_NOWRITE, &ncid) != NC_NOERR) {
        return 0;
    }

    // 2. End define mode
    nc_enddef(ncid);

    // 3. Put variable
    nc_put_var(ncid, 0, Data); // Using Data as the variable data

    // 4. Close the file
    nc_close(ncid);

    // 5. Re-open the file
    if (nc_open("./dummy_file", NC_NOWRITE, &ncid) != NC_NOERR) {
        return 0;
    }

    // 6. Inquire variable ID
    if (nc_inq_varid(ncid, "dummy_var", &varid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // 7. Inquire variable filter (first call)
    nc_inq_var_filter(ncid, varid, &filter_id, &nparams, params);

    // 8. Inquire variable filter (second call)
    nc_inq_var_filter(ncid, varid, &filter_id, &nparams, params);

    // 9. Get variable as float
    nc_get_var_float(ncid, varid, &var_data);

    // 10. Final close
    nc_close(ncid);

    return 0;
}