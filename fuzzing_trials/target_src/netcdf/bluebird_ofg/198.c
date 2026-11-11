#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include "netcdf.h"

extern int nc_put_var_long(int ncid, int varid, const long *op);

int LLVMFuzzerTestOneInput_198(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(long)) {
        return 0;
    }

    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));
    long op = *(const long *)(data + sizeof(int) * 2);

    // Call the function-under-test
    nc_put_var_long(ncid, varid, &op);

    return 0;
}