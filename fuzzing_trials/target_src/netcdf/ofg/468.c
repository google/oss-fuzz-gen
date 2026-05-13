#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_468(const uint8_t *data, size_t size) {
    int ncid = 1; // Example non-zero file ID
    int varid = 1; // Example non-zero variable ID
    const char *name = "attribute_name"; // Example attribute name
    nc_type xtype = NC_USHORT; // Example data type
    size_t len = size / sizeof(unsigned short); // Calculate length based on input size
    const unsigned short *values = (const unsigned short *)data; // Cast data to unsigned short

    // Ensure we have at least one unsigned short to pass
    if (len == 0) {
        return 0;
    }

    // Call the function-under-test
    nc_put_att_ushort(ncid, varid, name, xtype, len, values);

    return 0;
}