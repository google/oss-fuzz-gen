#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_170(const uint8_t *data, size_t size) {
    // Ensure we have enough data to extract parameters
    if (size < 5) return 0;

    // Extract parameters from the data
    int ncid = (int)data[0];
    int varid = (int)data[1];

    // Use a portion of the data for the attribute name
    size_t name_len = (size - 2) < NC_MAX_NAME ? (size - 2) : NC_MAX_NAME - 1;
    char name[NC_MAX_NAME] = {0};
    for (size_t i = 0; i < name_len; i++) {
        name[i] = (char)data[i + 2];
    }
    name[name_len] = '\0'; // Null-terminate the string

    // Prepare output parameters
    nc_type xtype;
    size_t attlen;

    // Call the function-under-test
    nc_inq_att(ncid, varid, name, &xtype, &attlen);

    return 0;
}