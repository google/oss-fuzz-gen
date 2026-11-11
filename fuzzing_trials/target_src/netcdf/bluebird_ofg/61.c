#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_61(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + 1) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = *((int *)data);
    int varid = *((int *)(data + sizeof(int)));
    nc_type xtype = *((nc_type *)(data + sizeof(int) * 2));
    size_t att_len = size - (sizeof(int) * 2 + sizeof(nc_type) + 1);

    // Ensure attribute name is null-terminated
    const char *name = (const char *)(data + sizeof(int) * 2 + sizeof(nc_type));
    size_t name_len = strnlen(name, size - (sizeof(int) * 2 + sizeof(nc_type)));
    if (name_len == size - (sizeof(int) * 2 + sizeof(nc_type))) {
        return 0; // No null-terminator found
    }

    // Extract the attribute values
    const unsigned char *op = (const unsigned char *)(data + sizeof(int) * 2 + sizeof(nc_type) + name_len + 1);

    // Call the function-under-test
    nc_put_att_uchar(ncid, varid, name, xtype, att_len, op);

    return 0;
}