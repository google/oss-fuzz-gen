#include <stdint.h>
#include <stddef.h>
#include <netcdf.h>
#include <string.h>
#include <stdlib.h> // Include for malloc and free

int LLVMFuzzerTestOneInput_132(const uint8_t *data, size_t size) {
    if (size < sizeof(int) + sizeof(nc_type) + 1 + sizeof(int)) {
        return 0; // Ensure there is enough data to extract all parameters
    }

    int ncid = *((int *)data);
    data += sizeof(int);
    size -= sizeof(int);

    nc_type xtype = *((nc_type *)data);
    data += sizeof(nc_type);
    size -= sizeof(nc_type);

    // Ensure null-terminated string for field_name
    size_t field_name_length = strnlen((const char *)data, size);
    char *field_name = (char *)malloc(field_name_length + 1);
    if (field_name == NULL) {
        return 0; // Memory allocation failed
    }
    memcpy(field_name, data, field_name_length);
    field_name[field_name_length] = '\0';
    data += field_name_length + 1;
    size -= field_name_length + 1;

    int field_index;
    
    // Call the function-under-test
    nc_inq_compound_fieldindex(ncid, xtype, field_name, &field_index);

    free(field_name);
    return 0;
}