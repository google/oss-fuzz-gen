#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_394(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) * 3 + sizeof(nc_type) + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int index = 0;
    int ncid = *((int *)(data + index));
    index += sizeof(int);

    nc_type xtype = *((nc_type *)(data + index));
    index += sizeof(nc_type);

    int fieldid = *((int *)(data + index));
    index += sizeof(int);

    // Allocate memory for the name
    char *name = (char *)malloc(size - index + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data + index, size - index);
    name[size - index] = '\0'; // Null-terminate the string
    index += size - index;

    // Initialize other parameters
    size_t field_offset = 0;
    nc_type field_type = 0;
    int ndims = 0;
    int dims[NC_MAX_VAR_DIMS] = {0};

    // Call the function-under-test
    nc_inq_compound_field(ncid, xtype, fieldid, name, &field_offset, &field_type, &ndims, dims);

    // Clean up
    free(name);

    return 0;
}