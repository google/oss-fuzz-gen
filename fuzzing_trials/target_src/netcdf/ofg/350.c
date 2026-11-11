#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_350(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(nc_type) + 256) {
        return 0;
    }

    int ncid = *(int *)(data);
    nc_type xtype = *(nc_type *)(data + sizeof(int));
    char name[256];
    size_t namelen;
    nc_type base_type;
    size_t size_out;
    int classp;

    // Ensure name is null-terminated
    size_t name_size = size - (sizeof(int) + sizeof(nc_type));
    if (name_size > 255) {
        name_size = 255;
    }
    memcpy(name, data + sizeof(int) + sizeof(nc_type), name_size);
    name[name_size] = '\0';

    // Check if the inputs are valid before calling the function
    if (ncid >= 0 && xtype >= 0) {
        // Call the function-under-test
        int retval = nc_inq_user_type(ncid, xtype, name, &namelen, &base_type, &size_out, &classp);
        
        // Handle the return value to increase code coverage
        if (retval == NC_NOERR) {
            // Process the output values if needed
        }
    }

    return 0;
}