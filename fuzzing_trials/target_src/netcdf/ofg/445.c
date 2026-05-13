#include <stddef.h>
#include <stdint.h>
#include <netcdf.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_445(const uint8_t *data, size_t size) {
    // Ensure that the size is sufficient to extract necessary parameters
    if (size < sizeof(int) + sizeof(nc_type) + sizeof(int)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    nc_type xtype = *(const nc_type *)data;
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    int ndims = *(const int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    // Create a non-null name string
    const char *name = "var_name";

    // Allocate memory for dimension IDs and variable ID
    int *dimids = NULL;
    if (ndims > 0) {
        dimids = (int *)malloc(ndims * sizeof(int));
        if (dimids == NULL) {
            return 0;
        }
        // Initialize dimension IDs with non-null values
        for (int i = 0; i < ndims; i++) {
            dimids[i] = i;
        }
    }

    int varid;

    // Call the function-under-test
    nc_def_var(ncid, name, xtype, ndims, dimids, &varid);

    // Clean up
    if (dimids != NULL) {
        free(dimids);
    }

    return 0;
}