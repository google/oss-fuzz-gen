#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_425(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(nc_type) + sizeof(size_t) + sizeof(nc_type) + sizeof(int)) {
        return 0; // Ensure there's enough data to extract meaningful parameters
    }

    // Extract parameters from the input data
    int ncid = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    nc_type xtype = *(nc_type *)data;
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    // Ensure the name is null-terminated and non-empty
    size_t name_len = strnlen((const char *)data, size);
    if (name_len == 0 || name_len >= size) {
        return 0;
    }
    const char *name = (const char *)data;
    data += name_len + 1;
    size -= name_len + 1;

    size_t len = *(size_t *)data;
    data += sizeof(size_t);
    size -= sizeof(size_t);

    nc_type field_type = *(nc_type *)data;
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    int ndims = *(int *)data;
    data += sizeof(int);
    size -= sizeof(int);

    if (ndims <= 0 || size < ndims * sizeof(int)) {
        return 0; // Ensure ndims is positive and there's enough data for dims
    }

    // Allocate and initialize dims array from the remaining data
    int *dims = (int *)malloc(ndims * sizeof(int));
    if (dims == NULL) {
        return 0; // Exit if memory allocation fails
    }

    memcpy(dims, data, ndims * sizeof(int));

    // Call the function-under-test
    int result = nc_insert_array_compound(ncid, xtype, name, len, field_type, ndims, dims);

    // Free allocated memory
    free(dims);

    return 0;
}