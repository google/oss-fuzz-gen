#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_362(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract necessary parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    const char *name = (const char *)(data + sizeof(int) * 2);
    nc_type xtype = *((nc_type *)(data + sizeof(int) * 2 + 1));
    size_t len = *((size_t *)(data + sizeof(int) * 2 + 1 + sizeof(nc_type)));

    // Ensure len is not larger than the remaining data size
    if (len > (size - (sizeof(int) * 2 + 1 + sizeof(nc_type) + sizeof(size_t)))) {
        return 0;
    }

    const int *op = (const int *)(data + sizeof(int) * 2 + 1 + sizeof(nc_type) + sizeof(size_t));

    // Call the function-under-test
    nc_put_att_int(ncid, varid, name, xtype, len, op);

    return 0;
}