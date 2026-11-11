#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_426(const uint8_t *data, size_t size) {
    // Ensure the input size is large enough to extract meaningful data
    if (size < sizeof(int) * 2 + 1) {
        return 0;
    }

    // Extract integers from the input data
    int ncid = *(int *)data;
    int varid = *(int *)(data + sizeof(int));

    // Extract a string for the attribute name
    size_t attr_name_length = size - sizeof(int) * 2;
    char *attr_name = (char *)malloc(attr_name_length + 1);
    if (attr_name == NULL) {
        return 0;
    }
    memcpy(attr_name, data + sizeof(int) * 2, attr_name_length);
    attr_name[attr_name_length] = '\0'; // Null-terminate the string

    // Allocate memory for the float attribute
    float attr_value;
    
    // Call the function-under-test
    int result = nc_get_att_float(ncid, varid, attr_name, &attr_value);

    // Clean up
    free(attr_name);

    return 0;
}