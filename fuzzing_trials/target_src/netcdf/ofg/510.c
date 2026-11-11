#include <stdint.h>
#include <stddef.h>
#include <string.h>

// Assuming the function is defined in an external library
extern int nc_get_att_uint(int ncid, int varid, const char *name, unsigned int *ip);

int LLVMFuzzerTestOneInput_510(const uint8_t *data, size_t size) {
    // Ensure the input size is sufficient to extract parameters
    if (size < 8) {
        return 0;
    }

    // Extract parameters from the input data
    int ncid = (int)data[0];
    int varid = (int)data[1];
    
    // Ensure the string is null-terminated
    size_t name_length = size - 6; // Reserve space for ncid, varid, and null terminator
    char name[name_length + 1];
    memcpy(name, &data[2], name_length);
    name[name_length] = '\0';

    unsigned int ip;
    
    // Call the function-under-test
    nc_get_att_uint(ncid, varid, name, &ip);

    return 0;
}