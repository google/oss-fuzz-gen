#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_201(const uint8_t *data, size_t size) {
    // Initialize variables for the function call
    int ncid = 0; // NetCDF file ID, assuming 0 for fuzzing
    int varid = 0; // Variable ID, assuming 0 for fuzzing

    // Define some dimensions for the NetCDF variable
    size_t start[2] = {0, 0}; // Start indices for the data
    size_t count[2] = {1, 1}; // Count of elements to be written
    ptrdiff_t stride[2] = {1, 1}; // Stride between elements
    ptrdiff_t imap[2] = {1, 1}; // Mapping between memory and file

    // Ensure there is enough data to read a double
    if (size < sizeof(double)) {
        return 0;
    }

    // Use the input data as the double array
    const double *fp = (const double *)data;

    // Call the function-under-test
    nc_put_varm_double(ncid, varid, start, count, stride, imap, fp);

    return 0;
}