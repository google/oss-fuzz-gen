#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_369(const uint8_t *data, size_t size) {
    // Define and initialize variables for the function parameters
    int ncid = 1; // Example non-zero integer for netCDF file ID
    int varid = 1; // Example non-zero integer for variable ID
    const char *name = "attribute_name"; // Example attribute name
    nc_type xtype = NC_FLOAT; // Data type for the attribute
    size_t len = size / sizeof(float); // Length of the attribute array
    float *values = NULL;

    // Ensure size is suitable for float array
    if (len > 0) {
        // Allocate memory for the float array
        values = (float *)malloc(len * sizeof(float));
        if (values == NULL) {
            return 0; // Exit if memory allocation fails
        }

        // Copy data into the float array
        memcpy(values, data, len * sizeof(float));
    }

    // Call the function-under-test
    nc_put_att_float(ncid, varid, name, xtype, len, values);

    // Free allocated memory
    if (values != NULL) {
        free(values);
    }

    return 0;
}