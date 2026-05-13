#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_19(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the required parameters
    if (size < sizeof(int) + sizeof(nc_type) + sizeof(int) + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    nc_type xtype = *(const nc_type *)data;
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    int fieldid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Allocate memory for the field name and ensure it's null-terminated
    char fieldname[256];
    size_t fieldname_size = size < 255 ? size : 255;
    memcpy(fieldname, data, fieldname_size);
    fieldname[fieldname_size] = '\0';

    // Call the function-under-test
    nc_inq_compound_fieldname(ncid, xtype, fieldid, fieldname);

    return 0;
}