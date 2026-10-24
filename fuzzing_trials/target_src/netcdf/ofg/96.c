#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_96(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to extract necessary parameters
    if (size < sizeof(int) + sizeof(nc_type)) {
        return 0; // Not enough data to proceed
    }

    // Extract ncid and xtype from the input data
    int ncid = *(const int*)data;
    nc_type xtype = *(const nc_type*)(data + sizeof(int));

    // Initialize nfields
    size_t nfields = 0;

    // Call the function-under-test
    int result = nc_inq_compound_nfields(ncid, xtype, &nfields);

    // Use the result and nfields for further logic if needed
    // For fuzzing, we are primarily interested in calling the function

    return 0;
}