#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_29(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(nc_type) + sizeof(size_t)) {
        return 0; // Not enough data to proceed
    }

    // Extracting parameters from data
    int ncid = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    nc_type xtype = *(nc_type *)data;
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    char name[NC_MAX_NAME + 1]; // Buffer for name
    size_t name_len = size < NC_MAX_NAME ? size : NC_MAX_NAME;
    for (size_t i = 0; i < name_len; ++i) {
        name[i] = (char)data[i];
    }
    name[name_len] = '\0';

    size_t size_out;
    int ret = nc_inq_type(ncid, xtype, name, &size_out);

    // The return value and output parameters can be used for further checks
    // or assertions if needed.

    return 0;
}