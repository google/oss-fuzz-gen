#include <stdint.h>
#include <stddef.h>
#include "netcdf.h"
#include <string.h>

int LLVMFuzzerTestOneInput_117(const uint8_t *data, size_t size) {
    // Ensure size is sufficient for extracting a non-null string
    if (size < 2) {
        return 0;
    }

    // Initialize parameters for nc_inq_typeid
    int ncid = 0;  // Assuming a valid netCDF ID, adjust if necessary
    char type_name[256];  // Buffer to store the type name
    nc_type typeidp;  // Variable to store the type ID

    // Ensure the data is null-terminated and within buffer limits
    size_t copy_size = size < 255 ? size : 255;
    memcpy(type_name, data, copy_size);
    type_name[copy_size] = '\0';

    // Call the function under test
    nc_inq_typeid(ncid, type_name, &typeidp);

    return 0;
}