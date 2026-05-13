#include <stdint.h>
#include <stddef.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_64(const uint8_t *data, size_t size) {
    int ncid = 0; // Example netCDF file ID
    int varid = 0; // Example variable ID
    const char *name = "attribute_name"; // Example attribute name
    nc_type xtype = NC_SHORT; // Example netCDF data type
    size_t len = 1; // Example length of the attribute array
    short value = 42; // Example attribute value
    const short *op = &value; // Pointer to the attribute value

    // Call the function-under-test
    nc_put_att_short(ncid, varid, name, xtype, len, op);

    return 0;
}