#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_527(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid = 0; // Assuming a valid netCDF file ID
    nc_type xtype = NC_INT; // Assuming NC_INT as a valid type
    int fieldid = 0; // Assuming the first field in a compound type
    size_t offset = 0;

    // Call the function-under-test
    int result = nc_inq_compound_fieldoffset(ncid, xtype, fieldid, &offset);

    // Return 0 as the fuzzer's return value
    return 0;
}