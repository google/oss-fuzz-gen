#include <stddef.h>
#include <stdint.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_467(const uint8_t *data, size_t size) {
    // Ensure there is enough data to extract parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = *(const int *)data;
    int varid = *(const int *)(data + sizeof(int));
    const char *name = (const char *)(data + sizeof(int) * 2);
    nc_type xtype = *(const nc_type *)(data + sizeof(int) * 2 + 1);
    size_t len = *(const size_t *)(data + sizeof(int) * 2 + 1 + sizeof(nc_type));

    // Ensure len is within bounds of the remaining data
    if (len > (size - (sizeof(int) * 2 + 1 + sizeof(nc_type) + sizeof(size_t)))) {
        len = size - (sizeof(int) * 2 + 1 + sizeof(nc_type) + sizeof(size_t));
    }

    const unsigned short *value = (const unsigned short *)(data + sizeof(int) * 2 + 1 + sizeof(nc_type) + sizeof(size_t));

    // Call the function-under-test
    nc_put_att_ushort(ncid, varid, name, xtype, len, value);

    return 0;
}