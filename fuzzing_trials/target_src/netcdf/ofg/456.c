#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_456(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 0; // Assuming a valid netCDF file ID for testing
    int varid = 0; // Assuming a valid variable ID for testing
    const char *name = "attribute_name"; // Example attribute name
    nc_type xtype = NC_INT64; // Example netCDF type
    size_t len = size / sizeof(long long); // Calculate the number of elements
    const long long *values = (const long long *)data; // Cast data to long long array

    // Ensure there is at least one element to avoid passing NULL
    if (len == 0) {
        return 0;
    }

    // Call the function-under-test
    nc_put_att_longlong(ncid, varid, name, xtype, len, values);

    return 0;
}