#include <stddef.h>
#include <stdint.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_265(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract the required inputs
    if (size < sizeof(int) + sizeof(nc_type)) {
        return 0;
    }

    // Extract an integer from the data
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Extract an nc_type from the data
    nc_type xtype = *(const nc_type *)data;
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    // Initialize a size_t variable to store the number of fields
    size_t nfields = 0;

    // Call the function-under-test
    int result = nc_inq_compound_nfields(ncid, xtype, &nfields);

    // Return 0 to indicate the fuzzer should continue
    return 0;
}