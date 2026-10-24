#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_389(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 2 + sizeof(size_t) + sizeof(unsigned short)) {
        return 0;
    }

    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));
    const size_t *indexp = (const size_t *)(data + sizeof(int) * 2);
    const unsigned short *ushortp = (const unsigned short *)(data + sizeof(int) * 2 + sizeof(size_t));

    // Call the function-under-test
    nc_put_var1_ushort(ncid, varid, indexp, ushortp);

    return 0;
}