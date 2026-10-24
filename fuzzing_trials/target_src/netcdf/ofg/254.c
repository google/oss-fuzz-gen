#include <stddef.h>
#include <stdint.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_254(const uint8_t *data, size_t size) {
    // Ensure there is enough data for the parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + 1) {
        return 0;
    }

    // Extract parameters from the data
    int ncid = *(const int *)data;
    data += sizeof(int);
    int varid = *(const int *)data;
    data += sizeof(int);
    nc_type xtype = *(const nc_type *)data;
    data += sizeof(nc_type);
    size_t len = *(const size_t *)data;
    data += sizeof(size_t);

    // Ensure len does not exceed remaining data size
    len = len % (size - (sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t)));

    // Extract the name as a null-terminated string
    const char *name = (const char *)data;
    data += len;

    // Extract the unsigned int array
    const unsigned int *values = (const unsigned int *)data;

    // Call the function-under-test
    nc_put_att_uint(ncid, varid, name, xtype, len, values);

    return 0;
}