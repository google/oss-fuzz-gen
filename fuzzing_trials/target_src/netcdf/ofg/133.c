#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>
#include <string.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput_133(const uint8_t *data, size_t size) {
    // Ensure the data is large enough to extract necessary inputs
    if (size < 5) {
        return 0;
    }

    // Extract the inputs from the data
    int ncid = (int)data[0]; // Use the first byte as an integer for ncid
    nc_type xtype = (nc_type)data[1]; // Use the second byte as nc_type
    const char *name = (const char *)(data + 2); // Use the rest as a string for name
    int field_index;

    // Ensure the string is null-terminated
    size_t name_length = size - 2;
    char *name_copy = (char *)malloc(name_length + 1);
    if (name_copy == NULL) {
        return 0;
    }
    memcpy(name_copy, name, name_length);
    name_copy[name_length] = '\0';

    // Call the function-under-test
    nc_inq_compound_fieldindex(ncid, xtype, name_copy, &field_index);

    // Clean up
    free(name_copy);

    return 0;
}