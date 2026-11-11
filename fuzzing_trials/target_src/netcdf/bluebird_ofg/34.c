#include <stdint.h>
#include <stddef.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_34(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for extracting parameters
    if (size < sizeof(int) + sizeof(nc_type)) {
        return 0;
    }

    // Extract the integer parameter
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the nc_type parameter
    nc_type xtype = *(const nc_type *)data;
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    // Initialize the size_t pointer
    size_t compound_size = 0;

    // Call the function-under-test
    int result = nc_inq_compound_size(ncid, xtype, &compound_size);

    // The result and compound_size can be used for further checks if needed

    return 0;
}