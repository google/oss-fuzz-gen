#include <stdint.h>
#include <stddef.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_78(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 3) {
        return 0; // Ensure there is enough data for three integers
    }

    int ncid = *(const int *)(data);
    nc_type xtype = *(const int *)(data + sizeof(int));
    int fieldid = *(const int *)(data + 2 * sizeof(int));

    // Allocate an array to store dimension sizes
    int dim_sizes[10]; // Assuming a maximum of 10 dimensions for demonstration

    // Call the function under test
    int result = nc_inq_compound_fielddim_sizes(ncid, xtype, fieldid, dim_sizes);

    // Use the result in some way to avoid compiler optimizations removing the call
    if (result == NC_NOERR) {
        // Process dim_sizes if needed
    }

    return 0;
}