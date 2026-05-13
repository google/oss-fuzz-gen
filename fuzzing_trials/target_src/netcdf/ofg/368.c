#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_368(const uint8_t *data, size_t size) {
    // Define and initialize parameters for nc_put_att_ulonglong
    int ncid = 0; // Assuming a valid netCDF file ID
    int varid = 0; // Assuming a valid variable ID
    const char *name = "attribute_name"; // Attribute name
    nc_type xtype = NC_UINT64; // Attribute type
    size_t len = size / sizeof(unsigned long long); // Length of the attribute data
    const unsigned long long *value = (const unsigned long long *)data; // Attribute data

    // Call the function-under-test
    nc_put_att_ulonglong(ncid, varid, name, xtype, len, value);

    return 0;
}