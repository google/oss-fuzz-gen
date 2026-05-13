#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_366(const uint8_t *data, size_t size) {
    // Declare and initialize variables for the function parameters
    int ncid = 1; // Example non-zero value for a netCDF file ID
    int varid = 1; // Example non-zero value for a variable ID
    int no_fill = 0; // Initialize no_fill to zero
    int fill_value_int = 0; // Example fill value for an integer variable

    // Call the function-under-test with the initialized parameters
    nc_inq_var_fill(ncid, varid, &no_fill, &fill_value_int);

    return 0;
}