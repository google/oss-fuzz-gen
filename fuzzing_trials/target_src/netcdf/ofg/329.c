#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>
#include <stdio.h>

int LLVMFuzzerTestOneInput_329(const uint8_t *data, size_t size) {
    // Create a temporary netCDF file
    const char *filename = "temp.nc";
    int ncid, varid;
    int retval;

    // Create a new netCDF file for writing
    if ((retval = nc_create(filename, NC_CLOBBER, &ncid))) {
        fprintf(stderr, "Error creating netCDF file: %s\n", nc_strerror(retval));
        return 0;
    }

    // Define dimensions
    int dimids[2];
    if ((retval = nc_def_dim(ncid, "dim0", 1, &dimids[0])) ||
        (retval = nc_def_dim(ncid, "dim1", 1, &dimids[1]))) {
        fprintf(stderr, "Error defining dimensions: %s\n", nc_strerror(retval));
        nc_close(ncid);
        return 0;
    }

    // Define a variable
    if ((retval = nc_def_var(ncid, "var", NC_UINT, 2, dimids, &varid))) {
        fprintf(stderr, "Error defining variable: %s\n", nc_strerror(retval));
        nc_close(ncid);
        return 0;
    }

    // End define mode
    if ((retval = nc_enddef(ncid))) {
        fprintf(stderr, "Error ending define mode: %s\n", nc_strerror(retval));
        nc_close(ncid);
        return 0;
    }

    // Define dimensions for the netCDF variable
    size_t start[2] = {0, 0}; // Starting indices
    size_t count[2] = {1, 1}; // Counts for each dimension
    ptrdiff_t stride[2] = {1, 1}; // Strides for each dimension
    ptrdiff_t imap[2] = {1, 1}; // Memory map for each dimension

    // Allocate memory for the unsigned int data
    unsigned int *values = (unsigned int *)malloc(sizeof(unsigned int) * count[0] * count[1]);
    if (values == NULL) {
        nc_close(ncid);
        return 0; // Exit if memory allocation fails
    }

    // Fill the values array with data from the fuzz input
    for (size_t i = 0; i < count[0] * count[1] && i < size / sizeof(unsigned int); i++) {
        values[i] = ((unsigned int *)data)[i];
    }

    // Call the function-under-test
    int result = nc_put_varm_uint(ncid, varid, start, count, stride, imap, values);

    // Free allocated memory
    free(values);

    // Close the netCDF file
    nc_close(ncid);

    // Remove the temporary netCDF file
    remove(filename);

    return 0;
}