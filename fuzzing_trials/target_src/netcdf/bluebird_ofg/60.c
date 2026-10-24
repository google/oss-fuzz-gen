#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_60(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract necessary parameters
    if (size < 10) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = (int)data[0];
    int varid = (int)data[1];
    const char *name = (const char *)&data[2];
    nc_type xtype = (nc_type)data[3];
    size_t len = (size_t)data[4];
    
    // Ensure the length does not exceed remaining data size
    if (len > size - 5) {
        len = size - 5;
    }

    const unsigned char *values = &data[5];

    // Call the function-under-test
    nc_put_att_ubyte(ncid, varid, name, xtype, len, values);

    return 0;
}