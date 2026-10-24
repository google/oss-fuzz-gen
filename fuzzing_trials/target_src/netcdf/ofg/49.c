#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_49(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our parameters
    if (size < sizeof(int) * 3) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)data);
    nc_type xtype = *((nc_type *)(data + sizeof(int)));
    int fieldid = *((int *)(data + sizeof(int) + sizeof(nc_type)));

    // Allocate memory for the output parameter
    int ndims;
    
    // Call the function-under-test
    nc_inq_compound_fieldndims(ncid, xtype, fieldid, &ndims);

    return 0;
}