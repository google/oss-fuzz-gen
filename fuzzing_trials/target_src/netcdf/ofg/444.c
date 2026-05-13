#include <stddef.h>
#include <stdint.h>
#include <netcdf.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_444(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient for our needs
    if (size < 12) {
        return 0;
    }

    // Extracting parameters from the data
    int ncid = (int)data[0]; // Using the first byte for ncid
    nc_type xtype = (nc_type)data[1]; // Using the second byte for nc_type
    int ndims = (int)data[2]; // Using the third byte for ndims

    if (ndims <= 0 || ndims > 10) {
        ndims = 1; // Ensure ndims is positive and reasonable
    }

    // Allocate memory for dimids and assign values from data
    int *dimids = (int *)malloc(ndims * sizeof(int));
    for (int i = 0; i < ndims; i++) {
        dimids[i] = (int)data[3 + i];
    }

    // Create a null-terminated string for the name
    size_t name_len = size - (3 + ndims);
    if (name_len > 255) {
        name_len = 255; // Limit the name length
    }
    char *name = (char *)malloc(name_len + 1);
    memcpy(name, &data[3 + ndims], name_len);
    name[name_len] = '\0'; // Null-terminate the string

    // Prepare for varid output
    int varid;

    // Call the function-under-test
    nc_def_var(ncid, name, xtype, ndims, dimids, &varid);

    // Clean up
    free(dimids);
    free(name);

    return 0;
}