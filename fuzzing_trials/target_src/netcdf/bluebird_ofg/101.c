#include <stdint.h>
#include <stddef.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_101(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient to extract parameters
    if (size < sizeof(int) * 3) {
        return 0;
    }

    // Extract parameters from data
    int ncid = *(int*)(data);
    nc_type xtype = *(nc_type*)(data + sizeof(int));
    int fieldid = *(int*)(data + 2 * sizeof(int));
    
    // Allocate memory for the output parameter
    nc_type field_type;
    
    // Call the function-under-test
    nc_inq_compound_fieldtype(ncid, xtype, fieldid, &field_type);

    return 0;
}