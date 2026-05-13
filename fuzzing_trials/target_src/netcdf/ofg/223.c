#include <stddef.h>
#include <stdint.h>
#include <netcdf.h>
#include <string.h> // Include for memset

int LLVMFuzzerTestOneInput_223(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(size_t) * 4 + sizeof(ptrdiff_t) * 2 + sizeof(unsigned short)) {
        return 0;
    }

    // Extract parameters from data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    const size_t *start = (const size_t *)(data + 2);
    const size_t *count = (const size_t *)(data + 2 + sizeof(size_t));
    const ptrdiff_t *stride = (const ptrdiff_t *)(data + 2 + sizeof(size_t) * 2);
    const ptrdiff_t *imap = (const ptrdiff_t *)(data + 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t));
    const unsigned short *value = (const unsigned short *)(data + 2 + sizeof(size_t) * 2 + sizeof(ptrdiff_t) * 2);

    // Initialize a NetCDF file and variable for testing
    int retval;
    int test_ncid, test_varid;
    size_t dim_len = 10; // Example dimension length
    int dimid;

    // Create a new NetCDF file in memory
    retval = nc_create_mem("test.nc", NC_CLOBBER | NC_NETCDF4, 0, NULL, &test_ncid);
    if (retval != NC_NOERR) return 0;

    // Define a dimension
    retval = nc_def_dim(test_ncid, "dim", dim_len, &dimid);
    if (retval != NC_NOERR) {
        nc_close(test_ncid);
        return 0;
    }

    // Define a variable
    retval = nc_def_var(test_ncid, "var", NC_USHORT, 1, &dimid, &test_varid);
    if (retval != NC_NOERR) {
        nc_close(test_ncid);
        return 0;
    }

    // End define mode
    retval = nc_enddef(test_ncid);
    if (retval != NC_NOERR) {
        nc_close(test_ncid);
        return 0;
    }

    // Prepare parameters for nc_put_varm_ushort
    size_t start_array[1] = {0}; // Start from the beginning
    size_t count_array[1] = {1}; // Write one element
    ptrdiff_t stride_array[1] = {1}; // Default stride
    ptrdiff_t imap_array[1] = {1}; // Default imap

    // Call the function under test
    nc_put_varm_ushort(test_ncid, test_varid, start_array, count_array, stride_array, imap_array, value);

    // Close the NetCDF file
    nc_close(test_ncid);

    return 0;
}