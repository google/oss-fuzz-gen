#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_277(const uint8_t *data, size_t size) {
    int ncid = 0; // Assuming a valid netCDF ID for testing
    int varid = 0; // Assuming a valid variable ID for testing
    nc_type xtype;
    
    // Ensure the data size is large enough to create a non-empty string
    if (size < 1) {
        return 0;
    }

    // Allocate memory for the attribute name and ensure it's null-terminated
    char *attname = (char *)malloc(size + 1);
    if (attname == NULL) {
        return 0;
    }
    memcpy(attname, data, size);
    attname[size] = '\0';

    // Call the function-under-test
    nc_inq_atttype(ncid, varid, attname, &xtype);

    // Free allocated memory
    free(attname);

    return 0;
}