#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>
#include <netcdf.h>

int LLVMFuzzerTestOneInput_522(const uint8_t *data, size_t size) {
    // Ensure the size is sufficient for extracting necessary parameters
    if (size < sizeof(int) + sizeof(size_t) + 1 + sizeof(nc_type)) {
        return 0;
    }

    // Extract the integer parameter
    int ncid;
    memcpy(&ncid, data, sizeof(int));
    data += sizeof(int);
    size -= sizeof(int);

    // Extract the size_t parameter
    size_t compound_size;
    memcpy(&compound_size, data, sizeof(size_t));
    data += sizeof(size_t);
    size -= sizeof(size_t);

    // Extract a non-null string for the name
    size_t name_length = size - sizeof(nc_type);
    char *name = (char *)malloc(name_length + 1);
    if (name == NULL) {
        return 0;
    }
    memcpy(name, data, name_length);
    name[name_length] = '\0';  // Ensure null-termination
    data += name_length;
    size -= name_length;

    // Extract the nc_type parameter
    nc_type xtype;
    memcpy(&xtype, data, sizeof(nc_type));

    // Call the function-under-test
    nc_def_compound(ncid, compound_size, name, &xtype);

    // Clean up
    free(name);

    return 0;
}