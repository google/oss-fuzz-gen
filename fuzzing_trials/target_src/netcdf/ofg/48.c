#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_48(const uint8_t *data, size_t size) {
    // Declare and initialize variables
    int ncid = 0; // Assuming a valid NetCDF ID, typically obtained from nc_open or nc_create
    nc_type xtype = NC_INT; // Using a valid nc_type, for example NC_INT
    int fieldid = 0; // Assuming an arbitrary field ID
    int ndims = 0; // To store the number of dimensions

    // Call the function-under-test
    int result = nc_inq_compound_fieldndims(ncid, xtype, fieldid, &ndims);

    // Return 0 to indicate the fuzzer should continue
    return 0;
}