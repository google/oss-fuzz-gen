#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_326(const uint8_t *data, size_t size) {
    // Ensure the size is large enough to extract necessary parameters
    if (size < sizeof(int) * 2 + sizeof(nc_type) + sizeof(size_t) + 1) {
        return 0;
    }

    int ncid = *(int *)(data); // Extracting the first int as ncid
    int varid = *(int *)(data + sizeof(int)); // Extracting the second int as varid
    const char *name = (const char *)(data + sizeof(int) * 2); // Extracting a string for name
    nc_type xtype = *(nc_type *)(data + sizeof(int) * 2 + sizeof(char *)); // Extracting nc_type
    size_t len = *(size_t *)(data + sizeof(int) * 2 + sizeof(char *) + sizeof(nc_type)); // Extracting size_t for len

    // Ensure len is within bounds of remaining data size
    if (len > size - (sizeof(int) * 2 + sizeof(char *) + sizeof(nc_type) + sizeof(size_t))) {
        len = size - (sizeof(int) * 2 + sizeof(char *) + sizeof(nc_type) + sizeof(size_t));
    }

    const signed char *values = (const signed char *)(data + sizeof(int) * 2 + sizeof(char *) + sizeof(nc_type) + sizeof(size_t));

    // Call the function under test
    nc_put_att_schar(ncid, varid, name, xtype, len, values);

    return 0;
}