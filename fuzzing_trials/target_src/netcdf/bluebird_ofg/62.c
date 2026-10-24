#include <stddef.h>
#include <stdint.h>
#include "netcdf.h"
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput_62(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(int *)data; // First int
    int varid = *(int *)(data + sizeof(int)); // Second int
    nc_type xtype = *(nc_type *)(data + 2 * sizeof(int)); // nc_type
    size_t len = *(size_t *)(data + 2 * sizeof(int) + sizeof(nc_type)); // size_t

    // Ensure len is not too large to avoid excessive memory allocation
    len = len % 1024; // Limit the length to a reasonable size

    // Allocate memory for the attribute name and attribute values
    const char *name = (const char *)(data + 2 * sizeof(int) + sizeof(nc_type) + sizeof(size_t));
    
    // Ensure the name is null-terminated
    size_t name_len = strnlen(name, size - (2 * sizeof(int) + sizeof(nc_type) + sizeof(size_t)));
    if (name_len == size - (2 * sizeof(int) + sizeof(nc_type) + sizeof(size_t))) {
        return 0; // Name is not null-terminated, exit early
    }

    char *name_copy = (char *)malloc(name_len + 1);
    if (!name_copy) {
        return 0; // Allocation failed, exit early
    }
    strncpy(name_copy, name, name_len);
    name_copy[name_len] = '\0';

    // Allocate memory for values
    int *values = (int *)malloc(len * sizeof(int));
    if (!values) {
        free(name_copy);
        return 0; // Allocation failed, exit early
    }

    // Copy the remaining data into the values array
    size_t values_offset = 2 * sizeof(int) + sizeof(nc_type) + sizeof(size_t) + name_len + 1;
    if (values_offset > size) {
        free(values);
        free(name_copy);
        return 0; // Offset exceeds available data, exit early
    }

    size_t values_size = size - values_offset;
    memcpy(values, data + values_offset, values_size < len * sizeof(int) ? values_size : len * sizeof(int));

    // Call the function-under-test
    nc_put_att_int(ncid, varid, name_copy, xtype, len, values);

    // Clean up
    free(values);
    free(name_copy);

    return 0;
}