#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_112(const uint8_t *data, size_t size) {
    // Define and initialize variables
    int ncid, varid;
    int retval;
    size_t start[] = {0}; // Start index for each dimension
    size_t count[] = {1}; // Count of elements to read along each dimension
    ptrdiff_t stride[] = {1}; // Stride along each dimension
    ptrdiff_t imap[] = {1}; // Mapping of memory to file data
    unsigned char value = 0; // Value to write, initialized to 0

    // Ensure the data size is sufficient for the value
    if (size < 2) {
        return 0;
    }

    // Use the first byte of data to set the value
    value = data[0];

    // Use the second byte of data to define the dimension size
    size_t dim_size = data[1] % 10 + 1; // Ensure dimension size is at least 1

    // Create a new netCDF file in memory
    if ((retval = nc_create_mem("fuzz_test.nc", NC_CLOBBER | NC_NETCDF4, NULL, 0, &ncid)))
        return 0; // Return if creation fails

    // Define a dimension
    int dimid;
    if ((retval = nc_def_dim(ncid, "dim", dim_size, &dimid)))
        return 0; // Return if dimension definition fails

    // Define a variable
    if ((retval = nc_def_var(ncid, "var", NC_UBYTE, 1, &dimid, &varid)))
        return 0; // Return if variable definition fails

    // End define mode
    if ((retval = nc_enddef(ncid)))
        return 0; // Return if ending define mode fails

    // Call the function-under-test
    int result = nc_put_varm_uchar(ncid, varid, start, count, stride, imap, &value);

    // Close the netCDF file
    nc_close(ncid);

    // Return 0 to indicate the fuzzer should continue
    return 0;
}