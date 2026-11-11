#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "netcdf.h"

int LLVMFuzzerTestOneInput_59(const uint8_t *data, size_t size) {
    // Check if the input size is sufficient to extract necessary parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t)) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(int *)data;
    int varid = *(int *)(data + sizeof(int));
    nc_type xtype = *(nc_type *)(data + sizeof(int) * 2);
    size_t len = *(size_t *)(data + sizeof(int) * 2 + sizeof(nc_type));

    // Ensure len is reasonable to avoid excessive memory allocation
    len = len % 100;  // Limit the length to 100 for safety

    // Calculate the remaining size for the attribute name and long array
    size_t remaining_size = size - (sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t));

    // Allocate and copy attribute name from the remaining data
    char *name = (char *)malloc(remaining_size + 1);
    if (!name) {
        return 0;
    }
    memcpy(name, data + sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t), remaining_size);
    name[remaining_size] = '\0';  // Null-terminate the string

    // Allocate and initialize the long array
    long *values = (long *)malloc(len * sizeof(long));
    if (!values) {
        free(name);
        return 0;
    }
    for (size_t i = 0; i < len; ++i) {
        values[i] = (long)i;  // Initialize with some values
    }

    // Call the function-under-test
    nc_put_att_long(ncid, varid, name, xtype, len, values);

    // Clean up
    free(name);
    free(values);

    return 0;
}