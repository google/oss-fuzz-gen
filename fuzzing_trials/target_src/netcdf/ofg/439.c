#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_439(const uint8_t *data, size_t size) {
    int ncid = 1; // Example non-zero file ID
    int varid = 1; // Example non-zero variable ID
    const char *name = "example_attribute"; // Example attribute name
    nc_type xtype = NC_UBYTE; // Example NetCDF data type
    size_t len = (size > 0) ? size : 1; // Ensure len is at least 1
    const unsigned char *value = data; // Use the provided data as the attribute value

    // Call the function-under-test
    nc_put_att_uchar(ncid, varid, name, xtype, len, value);

    return 0;
}