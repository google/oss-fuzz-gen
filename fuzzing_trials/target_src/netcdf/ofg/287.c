#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_287(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to extract necessary parameters
    if (size < 10) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = (int)data[0];
    int varid = (int)data[1];
    nc_type xtype = (nc_type)data[2];
    size_t len = (size_t)data[3];

    // Ensure len does not exceed the remaining data size
    if (len > size - 4) {
        len = size - 4;
    }

    // Extract attribute name and attribute values
    const char *name = (const char *)(data + 4);
    const void *value = (const void *)(data + 4 + len);

    // Call the function-under-test
    nc_put_att(ncid, varid, name, xtype, len, value);

    return 0;
}