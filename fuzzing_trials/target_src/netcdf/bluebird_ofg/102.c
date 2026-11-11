#include <stdint.h>
#include <stddef.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_102(const uint8_t *data, size_t size) {
    if (size < 6) {
        return 0; // Ensure there is enough data for ncid, xtype, and fieldid
    }

    // Use the first few bytes of data to set up parameters
    int ncid = data[0]; // Use the first byte as ncid
    nc_type xtype = data[1]; // Use the second byte as xtype
    int fieldid = data[2]; // Use the third byte as fieldid
    size_t offset;

    // Call the function-under-test
    int result = nc_inq_compound_fieldoffset(ncid, xtype, fieldid, &offset);

    // The result and offset can be used for further checks or logging if necessary
    // For example, log the result and offset to see if they change with different inputs
    // printf("Result: %d, Offset: %zu\n", result, offset);

    return 0;
}