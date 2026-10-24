#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>
#include <string.h>

int LLVMFuzzerTestOneInput_18(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract necessary parameters
    if (size < sizeof(int) * 3 + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)(data);
    nc_type xtype = *(const nc_type *)(data + sizeof(int));
    int fieldid = *(const int *)(data + sizeof(int) + sizeof(nc_type));

    // Allocate memory for the field name
    char fieldname[NC_MAX_NAME + 1]; // Ensure it is large enough for a name
    memset(fieldname, 0, sizeof(fieldname)); // Initialize to zero

    // Call the function-under-test
    nc_inq_compound_fieldname(ncid, xtype, fieldid, fieldname);

    return 0;
}