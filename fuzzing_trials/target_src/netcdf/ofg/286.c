#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>
#include <string.h>

int LLVMFuzzerTestOneInput_286(const uint8_t *data, size_t size) {
    // Ensure the data size is sufficient for our needs
    if (size < 10) {
        return 0;
    }

    // Extract values from the input data
    int ncid = (int)data[0];  // Use the first byte for ncid
    int varid = (int)data[1]; // Use the second byte for varid
    nc_type xtype = (nc_type)data[2]; // Use the third byte for nc_type

    // Use the rest of the data as the attribute name and attribute values
    const char *name = (const char *)&data[3];
    size_t name_len = strnlen(name, size - 3);
    if (name_len == size - 3) {
        return 0; // Ensure null-terminated string
    }

    // Calculate the remaining size for attribute values
    const void *value = (const void *)&data[3 + name_len + 1];
    size_t value_len = size - (3 + name_len + 1);

    // Call the function-under-test
    nc_put_att(ncid, varid, name, xtype, value_len, value);

    return 0;
}