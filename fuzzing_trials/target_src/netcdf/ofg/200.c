#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_200(const uint8_t *data, size_t size) {
    if (size < sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2 + sizeof(double)) {
        return 0;
    }

    int ncid = 0;  // Assuming a valid netCDF file ID
    int varid = 0; // Assuming a valid variable ID

    const size_t *start = (const size_t *)data;
    const size_t *count = (const size_t *)(data + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + sizeof(size_t) * 2);
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t));
    const double *value = (const double *)(data + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2);

    // Call the function-under-test
    int result = nc_put_varm_double(ncid, varid, start, count, stride, imap, value);

    // Handle the result if necessary
    if (result != NC_NOERR) {
        fprintf(stderr, "Error: %s\n", nc_strerror(result));
    }

    return 0;
}