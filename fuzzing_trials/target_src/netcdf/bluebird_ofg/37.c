#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include "netcdf.h"
#include <stdio.h>

int LLVMFuzzerTestOneInput_37(const uint8_t *data, size_t size) {
    // Create a temporary netCDF file and define a variable within it
    int ncid;
    int varid;
    int dimids[3];
    size_t dimlen = 10; // Example dimension length

    // Create a temporary netCDF file
    if (nc_create("temp.nc", NC_CLOBBER, &ncid) != NC_NOERR) {
        return 0;
    }

    // Define dimensions
    for (int i = 0; i < 3; ++i) {
        if (nc_def_dim(ncid, "dim", dimlen, &dimids[i]) != NC_NOERR) {
            nc_close(ncid);
            return 0;
        }
    }

    // Define a variable
    if (nc_def_var(ncid, "var", NC_FLOAT, 3, dimids, &varid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // End define mode
    if (nc_enddef(ncid) != NC_NOERR) {
        nc_close(ncid);
        return 0;
    }

    // Define dimensions for the netCDF variable
    size_t start[3] = {0, 0, 0}; // Start index for each dimension
    size_t count[3] = {dimlen, dimlen, dimlen}; // Write more elements in each dimension
    ptrdiff_t stride[3] = {1, 1, 1}; // Stride between elements in each dimension
    ptrdiff_t imap[3] = {1, 1, 1}; // Mapping of memory layout to file layout

    // Allocate a buffer for the data to write
    size_t total_elements = count[0] * count[1] * count[2];
    void *data_buffer = malloc(total_elements * sizeof(float)); // Assuming float data type

    if (data_buffer == NULL) {
        nc_close(ncid);
        return 0; // Exit if memory allocation fails
    }

    // Fill the buffer with some data from the input
    for (size_t i = 0; i < total_elements; ++i) {
        if (i < size) {
            ((float *)data_buffer)[i] = (float)data[i] / 255.0f; // Normalize input data
        } else {
            ((float *)data_buffer)[i] = 0.0f; // Fill with zero if input data is insufficient
        }
    }

    // Randomly modify start, count, stride, and imap to explore more code paths
    if (size >= 12) {
        start[0] = data[0] % dimlen;
        start[1] = data[1] % dimlen;
        start[2] = data[2] % dimlen;
        count[0] = (data[3] % dimlen) + 1;
        count[1] = (data[4] % dimlen) + 1;
        count[2] = (data[5] % dimlen) + 1;
        stride[0] = (data[6] % 3) + 1;
        stride[1] = (data[7] % 3) + 1;
        stride[2] = (data[8] % 3) + 1;
        imap[0] = (data[9] % 3) + 1;
        imap[1] = (data[10] % 3) + 1;
        imap[2] = (data[11] % 3) + 1;
    }

    // Call the function-under-test
    int result = nc_put_varm(ncid, varid, start, count, stride, imap, data_buffer);

    // Free the allocated buffer
    free(data_buffer);

    // Close the netCDF file
    nc_close(ncid);

    return result == NC_NOERR ? 1 : 0; // Return 1 if successful, 0 otherwise
}