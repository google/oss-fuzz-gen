#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_124(const uint8_t *data, size_t size) {
    if (size < sizeof(int)) {
        return 0; // Not enough data to proceed
    }

    int ncid = 0; // Initialize with a non-NULL value
    nc_type xtype = NC_INT; // Use a valid nc_type
    size_t compound_size; // Variable to store the size

    // Call the function-under-test
    int result = nc_inq_compound_size(ncid, xtype, &compound_size);

    // Use the result and compound_size in some way to avoid compiler optimizations
    if (result == NC_NOERR) {
        // Do something with compound_size
        (void)compound_size; // Suppress unused variable warning
    }

    return 0;
}