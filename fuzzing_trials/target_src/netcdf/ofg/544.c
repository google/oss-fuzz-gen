#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_544(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our parameters
    if (size < 12) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *((int *)(data));
    int varid = *((int *)(data + 4));
    int attid;
    
    // Calculate the remaining size for the name
    size_t name_length = size - 8;
    
    // Allocate memory for the attribute name and copy the data
    char *name = (char *)malloc(name_length + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + 8, name_length);
    name[name_length] = '\0'; // Null-terminate the string

    // Call the function-under-test
    int result = nc_inq_attid(ncid, varid, name, &attid);

    // Clean up
    free(name);

    return 0;
}