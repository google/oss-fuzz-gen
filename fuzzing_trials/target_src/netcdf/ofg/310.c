#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_310(const uint8_t *data, size_t size) {
    int ncid = 1;  // Dummy non-zero value for testing
    int varid = 1; // Dummy non-zero value for testing
    const char *name = "attribute_name"; // Dummy attribute name
    nc_type xtype = NC_LONG; // Use NC_LONG as the type
    size_t len = size / sizeof(long); // Calculate the number of long elements

    // Ensure the data size is sufficient to interpret as an array of longs
    if (len == 0) {
        return 0;
    }

    // Cast the data to a long pointer
    const long *values = (const long *)data;

    // Call the function-under-test
    nc_put_att_long(ncid, varid, name, xtype, len, values);

    return 0;
}