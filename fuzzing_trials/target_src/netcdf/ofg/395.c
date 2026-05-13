#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <netcdf.h>

#ifdef __cplusplus
extern "C" {
#endif

int LLVMFuzzerTestOneInput_395(const uint8_t *data, size_t size) {
    if (size < sizeof(int) * 3 + sizeof(nc_type)) {
        return 0; // Not enough data to proceed
    }

    int ncid = *(const int *)(data);
    nc_type xtype = *(const nc_type *)(data + sizeof(int));
    int fieldid = *(const int *)(data + sizeof(int) + sizeof(nc_type));

    char name[256];
    size_t offset;
    nc_type field_type;
    int ndims;
    int dims[NC_MAX_VAR_DIMS];

    // Ensure name is null-terminated
    size_t name_len = size - (sizeof(int) * 3 + sizeof(nc_type));
    if (name_len > 255) {
        name_len = 255;
    }
    for (size_t i = 0; i < name_len; ++i) {
        name[i] = data[sizeof(int) * 3 + sizeof(nc_type) + i];
    }
    name[name_len] = '\0';

    // Call the function-under-test
    nc_inq_compound_field(ncid, xtype, fieldid, name, &offset, &field_type, &ndims, dims);

    return 0;
}

#ifdef __cplusplus
}
#endif