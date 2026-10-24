#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_10(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our parameters
    if (size < sizeof(int) * 3) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)(data);
    nc_type xtype = *(const nc_type *)(data + sizeof(int));
    int fieldid = *(const int *)(data + sizeof(int) * 2);

    // Allocate memory for the output parameter
    nc_type field_type;
    
    // Call the function-under-test
    int result = nc_inq_compound_fieldtype(ncid, xtype, fieldid, &field_type);

    // Use the result and field_type to potentially verify or log results
    // (This is just a placeholder; actual verification would depend on the context)
    (void)result;
    (void)field_type;

    return 0;
}